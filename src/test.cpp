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
#define TEST_BLOCK(x, y, z) new_block_from_generator(*data, users, x, #x, y, z)

using namespace tangent;

class tests
{
public:
	struct account
	{
		ledger::wallet wallet;
		std::atomic<uint64_t> sequence;

		account() = default;
		account(const ledger::wallet& new_wallet, uint64_t new_sequence) : wallet(new_wallet), sequence(new_sequence)
		{
		}
		account(account&&) = default;
		account(const account& other) : wallet(other.wallet), sequence(other.sequence.load())
		{
		}
		account& operator= (account&&) = default;
		account& operator= (const account& other)
		{
			if (&other == this)
				return *this;

			wallet = other.wallet;
			sequence = other.sequence.load();
			return *this;
		}
	};

	class generators
	{
	public:
		static void adjustments(vector<uptr<ledger::transaction>>& transactions, vector<account>& users)
		{
			auto& [user2, user2_sequence] = users[1];
			auto* depository_adjustment_ethereum = memory::init<transactions::depository_adjustment>();
			depository_adjustment_ethereum->set_asset("ETH");
			depository_adjustment_ethereum->set_estimate_gas(decimal::zero());
			depository_adjustment_ethereum->set_incoming_fee(0.001, 0.0001);
			depository_adjustment_ethereum->set_outgoing_fee(0.001, 0.0001);
			VI_PANIC(depository_adjustment_ethereum->sign(user2.secret_key, user2_sequence++), "depository adjustment not signed");
			transactions.push_back(depository_adjustment_ethereum);

			auto* depository_adjustment_ripple = memory::init<transactions::depository_adjustment>();
			depository_adjustment_ripple->set_asset("XRP");
			depository_adjustment_ripple->set_estimate_gas(decimal::zero());
			depository_adjustment_ripple->set_incoming_fee(0.01, 0.0001);
			depository_adjustment_ripple->set_outgoing_fee(0.01, 0.0001);
			VI_PANIC(depository_adjustment_ripple->sign(user2.secret_key, user2_sequence++), "depository adjustment not signed");
			transactions.push_back(depository_adjustment_ripple);

			auto* depository_adjustment_bitcoin = memory::init<transactions::depository_adjustment>();
			depository_adjustment_bitcoin->set_asset("BTC");
			depository_adjustment_bitcoin->set_estimate_gas(decimal::zero());
			depository_adjustment_bitcoin->set_incoming_fee(0.00001, 0.0001);
			depository_adjustment_bitcoin->set_outgoing_fee(0.00001, 0.0001);
			VI_PANIC(depository_adjustment_bitcoin->sign(user2.secret_key, user2_sequence++), "depository adjustment not signed");
			transactions.push_back(depository_adjustment_bitcoin);
		}
		static void address_accounts(vector<uptr<ledger::transaction>>& transactions, vector<account>& users)
		{
			auto& [user1, user1_sequence] = users[0];
			auto& [user2, user2_sequence] = users[1];
			auto* address_account_ethereum1 = memory::init<transactions::address_account>();
			address_account_ethereum1->set_asset("ETH");
			address_account_ethereum1->set_estimate_gas(decimal::zero());
			address_account_ethereum1->set_address("0xCa0dfDdBb1cBD7B5A08E9173D9bbE5722138d4d5");
			VI_PANIC(address_account_ethereum1->sign(user1.secret_key, user1_sequence++), "account not signed");
			transactions.push_back(address_account_ethereum1);

			auto* address_account_ethereum2 = memory::init<transactions::address_account>();
			address_account_ethereum2->set_asset("ETH");
			address_account_ethereum2->set_estimate_gas(decimal::zero());
			address_account_ethereum2->set_address("0x89a0181659bd280836A2d33F57e3B5Dfa1a823CE");
			VI_PANIC(address_account_ethereum2->sign(user2.secret_key, user2_sequence++), "account not signed");
			transactions.push_back(address_account_ethereum2);

			auto* address_account_ripple1 = memory::init<transactions::address_account>();
			address_account_ripple1->set_asset("XRP");
			address_account_ripple1->set_estimate_gas(decimal::zero());
			address_account_ripple1->set_address("rUBqz2JiRCT3gYZBnm28y5ME7e5UpSm2ok");
			VI_PANIC(address_account_ripple1->sign(user1.secret_key, user1_sequence++), "account not signed");
			transactions.push_back(address_account_ripple1);

			auto* address_account_ripple2 = memory::init<transactions::address_account>();
			address_account_ripple2->set_asset("XRP");
			address_account_ripple2->set_estimate_gas(decimal::zero());
			address_account_ripple2->set_address("rJGb4etn9GSwNHYVu7dNMbdiVgzqxaTSUG");
			VI_PANIC(address_account_ripple2->sign(user2.secret_key, user2_sequence++), "account not signed");
			transactions.push_back(address_account_ripple2);

			auto* address_account_bitcoin1 = memory::init<transactions::address_account>();
			address_account_bitcoin1->set_asset("BTC");
			address_account_bitcoin1->set_estimate_gas(decimal::zero());
			address_account_bitcoin1->set_address("mmtubFoJvXrBuBUQFf1RrowXUbsiPDYnYS");
			VI_PANIC(address_account_bitcoin1->sign(user1.secret_key, user1_sequence++), "account not signed");
			transactions.push_back(address_account_bitcoin1);

			auto* address_account_bitcoin2 = memory::init<transactions::address_account>();
			address_account_bitcoin2->set_asset("BTC");
			address_account_bitcoin2->set_estimate_gas(decimal::zero());
			address_account_bitcoin2->set_address("bcrt1p2w7gkghj7arrjy4c45kh7450458hr8dv9pu9576lx08uuh4je7eqgskm9v");
			VI_PANIC(address_account_bitcoin2->sign(user2.secret_key, user2_sequence++), "account not signed");
			transactions.push_back(address_account_bitcoin2);
		}
		static void pubkey_accounts(vector<uptr<ledger::transaction>>& transactions, vector<account>& users)
		{
			auto* server = nss::server_node::get();
			auto& [user1, user1_sequence] = users[0];
			auto ethereum_seed = *crypto::hash_raw(digests::SHA256(), string((char*)user1.public_key_hash, sizeof(user1.public_key_hash)) + "ETH");
			auto ethereum_wallet = server->new_signing_wallet(algorithm::asset::id_of("ETH"), server->new_master_wallet(algorithm::asset::id_of("ETH"), ethereum_seed).expect("master wallet not derived")).expect("signing wallet not derived");
			auto* pubkey_account_ethereum = memory::init<transactions::pubkey_account>();
			pubkey_account_ethereum->set_asset("ETH");
			pubkey_account_ethereum->set_estimate_gas(decimal::zero());
			pubkey_account_ethereum->set_pubkey(ethereum_wallet.verifying_key);
			pubkey_account_ethereum->sign_pubkey(ethereum_wallet.signing_key).expect("pubkey account not signed");
			VI_PANIC(pubkey_account_ethereum->sign(user1.secret_key, user1_sequence++), "account not signed");
			transactions.push_back(pubkey_account_ethereum);

			auto ripple_seed = *crypto::hash_raw(digests::SHA256(), string((char*)user1.public_key_hash, sizeof(user1.public_key_hash)) + "XRP");
			auto ripple_wallet = server->new_signing_wallet(algorithm::asset::id_of("XRP"), server->new_master_wallet(algorithm::asset::id_of("XRP"), ripple_seed).expect("master wallet not derived")).expect("signing wallet not derived");
			auto* pubkey_account_ripple = memory::init<transactions::pubkey_account>();
			pubkey_account_ripple->set_asset("XRP");
			pubkey_account_ripple->set_estimate_gas(decimal::zero());
			pubkey_account_ripple->set_pubkey(ripple_wallet.verifying_key);
			pubkey_account_ripple->sign_pubkey(ripple_wallet.signing_key).expect("pubkey account not signed");
			VI_PANIC(pubkey_account_ripple->sign(user1.secret_key, user1_sequence++), "account not signed");
			transactions.push_back(pubkey_account_ripple);

			auto bitcoin_seed = *crypto::hash_raw(digests::SHA256(), string((char*)user1.public_key_hash, sizeof(user1.public_key_hash)) + "BTC");
			auto bitcoin_wallet = server->new_signing_wallet(algorithm::asset::id_of("BTC"), server->new_master_wallet(algorithm::asset::id_of("BTC"), bitcoin_seed).expect("master wallet not derived")).expect("signing wallet not derived");
			auto* pubkey_account_bitcoin = memory::init<transactions::pubkey_account>();
			pubkey_account_bitcoin->set_asset("BTC");
			pubkey_account_bitcoin->set_estimate_gas(decimal::zero());
			pubkey_account_bitcoin->set_pubkey(bitcoin_wallet.verifying_key);
			pubkey_account_bitcoin->sign_pubkey(bitcoin_wallet.signing_key).expect("pubkey account not signed");
			VI_PANIC(pubkey_account_bitcoin->sign(user1.secret_key, user1_sequence++), "account not signed");
			transactions.push_back(pubkey_account_bitcoin);
		}
		static void commitments(vector<uptr<ledger::transaction>>& transactions, vector<account>& users)
		{
			auto& [user1, user1_sequence] = users[0];
			auto& [user2, user2_sequence] = users[1];
			auto* commitment_user1 = memory::init<transactions::commitment>();
			commitment_user1->set_asset("BTC");
			commitment_user1->set_estimate_gas(decimal::zero());
			commitment_user1->set_online(algorithm::asset::id_of("ETH"));
			commitment_user1->set_online(algorithm::asset::id_of("XRP"));
			commitment_user1->set_online(algorithm::asset::id_of("BTC"));

			auto context = ledger::transaction_context();
			auto user1_work = context.get_account_work(user1.public_key_hash);
			if (!user1_work || !user1_work->is_online())
				commitment_user1->set_online();

			VI_PANIC(commitment_user1->sign(user1.secret_key, user1_sequence++), "commitment not signed");
			transactions.push_back(commitment_user1);

			auto* commitment_user2 = memory::init<transactions::commitment>();
			commitment_user2->set_asset("BTC");
			commitment_user2->set_estimate_gas(decimal::zero());
			commitment_user2->set_online(algorithm::asset::id_of("ETH"));
			commitment_user2->set_online(algorithm::asset::id_of("XRP"));
			commitment_user2->set_online(algorithm::asset::id_of("BTC"));

			auto user2_work = context.get_account_work(user2.public_key_hash);
			if (!user2_work || !user2_work->is_online())
				commitment_user2->set_online();

			VI_PANIC(commitment_user2->sign(user2.secret_key, user2_sequence++), "commitment not signed");
			transactions.push_back(commitment_user2);
		}
		static void commitment_online(vector<uptr<ledger::transaction>>& transactions, vector<account>& users, size_t user_id)
		{
			auto& [user1, user1_sequence] = users[user_id];
			auto* commitment_user1 = memory::init<transactions::commitment>();
			commitment_user1->set_asset("BTC");
			commitment_user1->set_estimate_gas(decimal::zero());
			commitment_user1->set_online(algorithm::asset::id_of("ETH"));
			commitment_user1->set_online(algorithm::asset::id_of("XRP"));
			commitment_user1->set_online(algorithm::asset::id_of("BTC"));

			auto context = ledger::transaction_context();
			auto user1_work = context.get_account_work(user1.public_key_hash);
			if (!user1_work || !user1_work->is_online())
				commitment_user1->set_online();

			VI_PANIC(commitment_user1->sign(user1.secret_key, user1_sequence++), "commitment not signed");
			transactions.push_back(commitment_user1);
		}
		static void commitment_offline(vector<uptr<ledger::transaction>>& transactions, vector<account>& users, size_t user_id)
		{
			auto& [user1, user1_sequence] = users[user_id];
			auto* commitment_user1 = memory::init<transactions::commitment>();
			commitment_user1->set_asset("BTC");
			commitment_user1->set_estimate_gas(decimal::zero());
			commitment_user1->set_offline(algorithm::asset::id_of("ETH"));
			commitment_user1->set_offline(algorithm::asset::id_of("XRP"));
			commitment_user1->set_offline(algorithm::asset::id_of("BTC"));

			auto context = ledger::transaction_context();
			auto user1_work = context.get_account_work(user1.public_key_hash);
			if (!user1_work || user1_work->is_online())
				commitment_user1->set_offline();

			VI_PANIC(commitment_user1->sign(user1.secret_key, user1_sequence++), "commitment not signed");
			transactions.push_back(commitment_user1);
		}
		static void allocations(vector<uptr<ledger::transaction>>& transactions, vector<account>& users)
		{
			auto& [user1, user1_sequence] = users[0];
			auto& [user2, user2_sequence] = users[1];
			auto* contribution_allocation_ethereum1 = memory::init<transactions::contribution_allocation>();
			contribution_allocation_ethereum1->set_asset("ETH");
			contribution_allocation_ethereum1->set_estimate_gas(decimal::zero());
			VI_PANIC(contribution_allocation_ethereum1->sign(user1.secret_key, user1_sequence++), "depository allocation not signed");
			transactions.push_back(contribution_allocation_ethereum1);

			auto* contribution_allocation_ethereum2 = memory::init<transactions::contribution_allocation>();
			contribution_allocation_ethereum2->set_asset("ETH");
			contribution_allocation_ethereum2->set_estimate_gas(decimal::zero());
			VI_PANIC(contribution_allocation_ethereum2->sign(user2.secret_key, user2_sequence++), "depository allocation not signed");
			transactions.push_back(contribution_allocation_ethereum2);

			auto* contribution_allocation_ripple = memory::init<transactions::contribution_allocation>();
			contribution_allocation_ripple->set_asset("XRP");
			contribution_allocation_ripple->set_estimate_gas(decimal::zero());
			VI_PANIC(contribution_allocation_ripple->sign(user2.secret_key, user2_sequence++), "depository allocation not signed");
			transactions.push_back(contribution_allocation_ripple);

			auto* contribution_allocation_bitcoin = memory::init<transactions::contribution_allocation>();
			contribution_allocation_bitcoin->set_asset("BTC");
			contribution_allocation_bitcoin->set_estimate_gas(decimal::zero());
			VI_PANIC(contribution_allocation_bitcoin->sign(user2.secret_key, user2_sequence++), "depository allocation not signed");
			transactions.push_back(contribution_allocation_bitcoin);
		}
		static void contributions(vector<uptr<ledger::transaction>>& transactions, vector<account>& users)
		{
			auto& [user1, user1_sequence] = users[0];
			auto& [user2, user2_sequence] = users[1];
			auto context = ledger::transaction_context();
			auto addresses1 = *context.get_witness_addresses_by_purpose(user1.public_key_hash, states::address_type::contribution, 0, 128);
			auto addresses2 = *context.get_witness_addresses_by_purpose(user2.public_key_hash, states::address_type::contribution, 0, 128);
			auto address_ethereum1 = std::find_if(addresses1.begin(), addresses1.end(), [](states::witness_address& item) { return item.asset == algorithm::asset::id_of("ETH"); });
			auto address_ethereum2 = std::find_if(addresses2.begin(), addresses2.end(), [](states::witness_address& item) { return item.asset == algorithm::asset::id_of("ETH"); });
			auto address_ripple = std::find_if(addresses2.begin(), addresses2.end(), [](states::witness_address& item) { return item.asset == algorithm::asset::id_of("XRP"); });
			auto address_bitcoin = std::find_if(addresses2.begin(), addresses2.end(), [](states::witness_address& item) { return item.asset == algorithm::asset::id_of("BTC"); });
			VI_PANIC(address_ethereum1 != addresses1.end(), "ethereum custodian address not found");
			VI_PANIC(address_ethereum2 != addresses2.end(), "ethereum custodian address not found");
			VI_PANIC(address_ripple != addresses2.end(), "ripple custodian address not found");
			VI_PANIC(address_bitcoin != addresses2.end(), "bitcoin custodian address not found");

			auto* incoming_claim_ethereum1 = memory::init<transactions::incoming_claim>();
			incoming_claim_ethereum1->set_asset("ETH");
			incoming_claim_ethereum1->set_estimate_gas(decimal::zero());
			incoming_claim_ethereum1->set_witness(14977180,
				"0x3bc2c98682f1b8feaacbde8f3f56494cd778da9d042da8439fb698d41bf060ea", 0.0,
				{ mediator::transferer("0xCa0dfDdBb1cBD7B5A08E9173D9bbE5722138d4d5", optional::none, 150) },
				{ mediator::transferer(address_ethereum1->addresses.begin()->second, address_ethereum1->address_index, 150) });
			VI_PANIC(incoming_claim_ethereum1->sign(user1.secret_key, user1_sequence++), "claim not signed");
			transactions.push_back(incoming_claim_ethereum1);

			auto* incoming_claim_ethereum2 = memory::init<transactions::incoming_claim>();
			incoming_claim_ethereum2->set_asset("ETH");
			incoming_claim_ethereum2->set_estimate_gas(decimal::zero());
			incoming_claim_ethereum2->set_witness(14977181,
				"0x7bc2c98682f1b8fea2031e8f3f56494cd778da9d042da8439fb698d41bf061ea", 0.0,
				{ mediator::transferer("0xCa0dfDdBb1cBD7B5A08E9173D9bbE5722138d4d5", optional::none, 110) },
				{ mediator::transferer(address_ethereum2->addresses.begin()->second, address_ethereum2->address_index, 110) });
			VI_PANIC(incoming_claim_ethereum2->sign(user2.secret_key, user2_sequence++), "claim not signed");
			transactions.push_back(incoming_claim_ethereum2);

			auto* incoming_claim_ripple = memory::init<transactions::incoming_claim>();
			incoming_claim_ripple->set_asset("XRP");
			incoming_claim_ripple->set_estimate_gas(decimal::zero());
			incoming_claim_ripple->set_witness(88546831,
				"6618D20B801AF96DD060B34228E2594E30AFB7B33E335A8C60199B6CF8B0A69F", 0.0,
				{ mediator::transferer("rUBqz2JiRCT3gYZBnm28y5ME7e5UpSm2ok", optional::none, 1100) },
				{ mediator::transferer(address_ripple->addresses.begin()->second, address_ripple->address_index, 1100) });
			VI_PANIC(incoming_claim_ripple->sign(user2.secret_key, user2_sequence++), "claim not signed");
			transactions.push_back(incoming_claim_ripple);

			auto* incoming_claim_bitcoin = memory::init<transactions::incoming_claim>();
			incoming_claim_bitcoin->set_asset("BTC");
			incoming_claim_bitcoin->set_estimate_gas(decimal::zero());
			incoming_claim_bitcoin->set_witness(846983,
				"17638131d9af3033a5e20b753af254e1e8321b2039f16dfd222f6b1117b5c69d", 0.0,
				{ mediator::transferer("mmtubFoJvXrBuBUQFf1RrowXUbsiPDYnYS", optional::none, 1.1) },
				{ mediator::transferer(address_bitcoin->addresses.begin()->second, address_bitcoin->address_index, 1.1) });
			VI_PANIC(incoming_claim_bitcoin->sign(user2.secret_key, user2_sequence++), "claim not signed");
			transactions.push_back(incoming_claim_bitcoin);
		}
		static void delegated_custodian_accounts(vector<uptr<ledger::transaction>>& transactions, vector<account>& users)
		{
			auto& [user1, user1_sequence] = users[0];
			auto& [user2, user2_sequence] = users[1];
			auto* delegation_account_ethereum = memory::init<transactions::delegation_account>();
			delegation_account_ethereum->set_asset("ETH");
			delegation_account_ethereum->set_estimate_gas(decimal::zero());
			delegation_account_ethereum->set_proposer(user2.public_key_hash);
			VI_PANIC(delegation_account_ethereum->sign(user2.secret_key, user2_sequence++), "account not signed");
			transactions.push_back(delegation_account_ethereum);

			auto* delegation_account_ripple = memory::init<transactions::delegation_account>();
			delegation_account_ripple->set_asset("XRP");
			delegation_account_ripple->set_estimate_gas(decimal::zero());
			delegation_account_ripple->set_proposer(user2.public_key_hash);
			VI_PANIC(delegation_account_ripple->sign(user1.secret_key, user1_sequence++), "account not signed");
			transactions.push_back(delegation_account_ripple);

			auto* delegation_account_bitcoin = memory::init<transactions::delegation_account>();
			delegation_account_bitcoin->set_asset("BTC");
			delegation_account_bitcoin->set_estimate_gas(decimal::zero());
			delegation_account_bitcoin->set_proposer(user2.public_key_hash);
			VI_PANIC(delegation_account_bitcoin->sign(user1.secret_key, user1_sequence++), "account not signed");
			transactions.push_back(delegation_account_bitcoin);
		}
		static void claims(vector<uptr<ledger::transaction>>& transactions, vector<account>& users)
		{
			auto& [user1, user1_sequence] = users[0];
			auto& [user2, user2_sequence] = users[1];
			auto context = ledger::transaction_context();
			auto proposer_addresses = *context.get_witness_addresses_by_purpose(user2.public_key_hash, states::address_type::custodian, 0, 128);
			auto owner_addresses = *context.get_witness_addresses_by_purpose(user1.public_key_hash, states::address_type::custodian, 0, 128);
			auto address_ethereum = std::find_if(proposer_addresses.begin(), proposer_addresses.end(), [](states::witness_address& item) { return item.asset == algorithm::asset::id_of("ETH"); });
			auto address_ripple = std::find_if(owner_addresses.begin(), owner_addresses.end(), [](states::witness_address& item) { return item.asset == algorithm::asset::id_of("XRP"); });
			auto address_bitcoin = std::find_if(owner_addresses.begin(), owner_addresses.end(), [](states::witness_address& item) { return item.asset == algorithm::asset::id_of("BTC"); });
			VI_PANIC(address_ethereum != proposer_addresses.end(), "ethereum custodian address not found");
			VI_PANIC(address_ripple != owner_addresses.end(), "ripple custodian address not found");
			VI_PANIC(address_bitcoin != owner_addresses.end(), "bitcoin custodian address not found");

			auto* incoming_claim_ethereum = memory::init<transactions::incoming_claim>();
			incoming_claim_ethereum->set_asset("ETH");
			incoming_claim_ethereum->set_estimate_gas(decimal::zero());
			incoming_claim_ethereum->set_witness(14977180,
				"0x2bc2c98682f1b8fea2031e8f3f56494cd778da9d042da8439fb698d41bf061ea", 0.0,
				{ mediator::transferer("0xCa0dfDdBb1cBD7B5A08E9173D9bbE5722138d4d5", optional::none, 100) },
				{ mediator::transferer(address_ethereum->addresses.begin()->second, address_ethereum->address_index, 100) });
			VI_PANIC(incoming_claim_ethereum->sign(user2.secret_key, user2_sequence++), "claim not signed");
			transactions.push_back(incoming_claim_ethereum);

			auto* incoming_claim_ripple = memory::init<transactions::incoming_claim>();
			incoming_claim_ripple->set_asset("XRP");
			incoming_claim_ripple->set_estimate_gas(decimal::zero());
			incoming_claim_ripple->set_witness(88546830,
				"2618D20B801AF96DD060B34228E2594E30AFB7B33E335A8C60199B6CF8B0A69F", 0.0,
				{ mediator::transferer("rUBqz2JiRCT3gYZBnm28y5ME7e5UpSm2ok", optional::none, 1000) },
				{ mediator::transferer(address_ripple->addresses.begin()->second, address_ripple->address_index, 1000) });
			VI_PANIC(incoming_claim_ripple->sign(user2.secret_key, user2_sequence++), "claim not signed");
			transactions.push_back(incoming_claim_ripple);

			auto* incoming_claim_bitcoin = memory::init<transactions::incoming_claim>();
			incoming_claim_bitcoin->set_asset("BTC");
			incoming_claim_bitcoin->set_estimate_gas(decimal::zero());
			incoming_claim_bitcoin->set_witness(846982,
				"57638131d9af3033a5e20b753af254e1e8321b2039f16dfd222f6b1117b5c69d", 0.0,
				{ mediator::transferer("mmtubFoJvXrBuBUQFf1RrowXUbsiPDYnYS", optional::none, 1.0) },
				{ mediator::transferer(address_bitcoin->addresses.begin()->second, address_bitcoin->address_index, 1.0) });
			VI_PANIC(incoming_claim_bitcoin->sign(user2.secret_key, user2_sequence++), "claim not signed");
			transactions.push_back(incoming_claim_bitcoin);
		}
		static void transfers(vector<uptr<ledger::transaction>>& transactions, vector<account>& users)
		{
			auto& [user1, user1_sequence] = users[0];
			auto& [user2, user2_sequence] = users[1];
			auto* omnitransfer_ethereum = memory::init<transactions::omnitransfer>();
			omnitransfer_ethereum->set_asset("ETH");
			omnitransfer_ethereum->set_to(user2.public_key_hash, 0.1);
			omnitransfer_ethereum->set_to(user2.public_key_hash, 0.2);
			omnitransfer_ethereum->set_to(user2.public_key_hash, 0.3);
			omnitransfer_ethereum->set_to(user2.public_key_hash, 0.4);
			omnitransfer_ethereum->set_to(user2.public_key_hash, 0.5);
			omnitransfer_ethereum->set_estimate_gas(std::string_view("0.00000001"));
			VI_PANIC(omnitransfer_ethereum->sign(user1.secret_key, user1_sequence++), "omnitransfer not signed");
			transactions.push_back(omnitransfer_ethereum);

			auto* transfer_ripple = memory::init<transactions::transfer>();
			transfer_ripple->set_asset("XRP");
			transfer_ripple->set_to(user2.public_key_hash, 10.0);
			transfer_ripple->set_estimate_gas(std::string_view("0.000068"));
			VI_PANIC(transfer_ripple->sign(user1.secret_key, user1_sequence++), "transfer not signed");
			transactions.push_back(transfer_ripple);

			auto* transfer_bitcoin = memory::init<transactions::transfer>();
			transfer_bitcoin->set_asset("BTC");
			transfer_bitcoin->set_to(user2.public_key_hash, 0.1);
			transfer_bitcoin->set_estimate_gas(std::string_view("0.0000000005"));
			VI_PANIC(transfer_bitcoin->sign(user1.secret_key, user1_sequence++), "transfer not signed");
			transactions.push_back(transfer_bitcoin);
		}
		static void transfer_to_wallet(vector<uptr<ledger::transaction>>& transactions, vector<account>& users, size_t user_id, const algorithm::asset_id& asset, const std::string_view& address, const decimal& value)
		{
			auto& [user1, user1_sequence] = users[user_id];
			algorithm::pubkeyhash public_key_hash;
			algorithm::signing::decode_address(address, public_key_hash);

			auto* transfer_asset = memory::init<transactions::transfer>();
			transfer_asset->asset = asset;
			transfer_asset->set_to(public_key_hash, value);
			transfer_asset->set_estimate_gas(std::string_view("0.0000000005"));
			VI_PANIC(transfer_asset->sign(user1.secret_key, user1_sequence++), "transfer not signed");
			transactions.push_back(transfer_asset);
		}
		static void rollups(vector<uptr<ledger::transaction>>& transactions, vector<account>& users)
		{
			auto& [user1, user1_sequence] = users[0];
			auto& [user2, user2_sequence] = users[1];
			auto* multi_asset_rollup = memory::init<transactions::rollup>();
			multi_asset_rollup->set_asset("ETH");

			auto transfer_ethereum1 = transactions::transfer();
			transfer_ethereum1.set_to(user2.public_key_hash, 0.1);
			VI_PANIC(multi_asset_rollup->merge(transfer_ethereum1, user1.secret_key, user1_sequence++), "transfer not signed");

			auto transfer_ethereum2 = transactions::transfer();
			transfer_ethereum2.set_to(user2.public_key_hash, 0.2);
			VI_PANIC(multi_asset_rollup->merge(transfer_ethereum2, user1.secret_key, user1_sequence++), "transfer not signed");

			auto transfer_ethereum3 = transactions::transfer();
			transfer_ethereum3.set_to(user1.public_key_hash, 0.2);
			VI_PANIC(multi_asset_rollup->merge(transfer_ethereum3, user2.secret_key, user2_sequence++), "transfer not signed");

			auto transfer_ripple1 = transactions::transfer();
			transfer_ripple1.set_asset("XRP");
			transfer_ripple1.set_to(user2.public_key_hash, 1);
			VI_PANIC(multi_asset_rollup->merge(transfer_ripple1, user1.secret_key, user1_sequence++), "transfer not signed");

			auto transfer_ripple2 = transactions::transfer();
			transfer_ripple2.set_asset("XRP");
			transfer_ripple2.set_to(user2.public_key_hash, 2);
			VI_PANIC(multi_asset_rollup->merge(transfer_ripple2, user1.secret_key, user1_sequence++), "transfer not signed");

			auto transfer_ripple3 = transactions::transfer();
			transfer_ripple3.set_asset("XRP");
			transfer_ripple3.set_to(user1.public_key_hash, 2);
			VI_PANIC(multi_asset_rollup->merge(transfer_ripple3, user2.secret_key, user2_sequence++), "transfer not signed");

			auto transfer_bitcoin1 = transactions::transfer();
			transfer_bitcoin1.set_asset("BTC");
			transfer_bitcoin1.set_to(user2.public_key_hash, 0.001);
			VI_PANIC(multi_asset_rollup->merge(transfer_bitcoin1, user1.secret_key, user1_sequence++), "transfer not signed");

			auto transfer_bitcoin2 = transactions::transfer();
			transfer_bitcoin2.set_asset("BTC");
			transfer_bitcoin2.set_to(user2.public_key_hash, 0.002);
			VI_PANIC(multi_asset_rollup->merge(transfer_bitcoin2, user1.secret_key, user1_sequence++), "transfer not signed");

			auto transfer_bitcoin3 = transactions::transfer();
			transfer_bitcoin3.set_asset("BTC");
			transfer_bitcoin3.set_to(user1.public_key_hash, 0.002);
			VI_PANIC(multi_asset_rollup->merge(transfer_bitcoin3, user2.secret_key, user2_sequence++), "transfer not signed");

			multi_asset_rollup->set_estimate_gas(std::string_view("0.00000001"));
			VI_PANIC(multi_asset_rollup->sign(user1.secret_key, user1_sequence++), "rollup not signed");
			transactions.push_back(multi_asset_rollup);
		}
		static void deployments(vector<uptr<ledger::transaction>>& transactions, vector<account>& users)
		{
			auto& [user1, user1_sequence] = users[0];
			ledger::wallet token_contract = ledger::wallet::from_seed(string("token") + string((char*)user1.secret_key, sizeof(user1.secret_key)));
			std::string_view token_program = VI_STRINGIFY(
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

			token_info initialize(program@ p, const uint256 & in value)
			{
				token_info token;
				token.owner = p.from();
				token.name = "Fiat Token";
				token.symbol = "F";
				token.decimals = 2;
				token.supply = value;

				token_balance output;
				output.owner = token.owner;
				output.value = value;

				p.store(p.to(), token);
				p.store(output.owner, output);
				return token;
			}
			token_transfer transfer(program@ p, const address & in to, const uint256 & in value)
			{
				address from = p.from();
				token_balance input;
				if (!p.load(from, input))
					input.owner = from;

				token_balance output;
				if (!p.load(to, output))
					output.owner = to;

				uint256 from_delta = input.value - value;
				if (from_delta > input.value)
					throw exception_ptr("logical_error", "from balance will underflow (" + input.value.to_string() + " < " + value.to_string() + ")");

				uint256 to_delta = output.value + value;
				if (to_delta < output.value)
					throw exception_ptr("argument_error", "to balance will overflow (" + output.value.to_string() + " + " + value.to_string() + " > uint256_max)");

				input.value = from_delta;
				output.value = to_delta;
				p.store(input.owner, input);
				p.store(output.owner, output);

				token_transfer event;
				event.from = input.owner;
				event.to = output.owner;
				event.value = value;
				return event;
			}
			uint256 mint(program@ p, const uint256 & in value)
			{
				token_info token;
				if (!p.load(p.to(), token) || token.owner != p.from())
					throw exception_ptr("logical_error", "from does not own the token");

				token_balance output;
				if (!p.load(token.owner, output))
					output.owner = token.owner;

				uint256 supply_delta = token.supply + value;
				if (supply_delta < token.supply)
					throw exception_ptr("argument_error", "token supply will overflow (" + output.value.to_string() + " + " + value.to_string() + " > uint256_max)");

				uint256 to_delta = output.value + value;
				if (to_delta < output.value)
					throw exception_ptr("argument_error", "owner balance will overflow (" + output.value.to_string() + " + " + value.to_string() + " > uint256_max)");

				token.supply = supply_delta;
				output.value = to_delta;
				p.store(p.to(), token);
				p.store(output.owner, output);
				return output.value;
			}
			uint256 burn(program@ p, const uint256 & in value)
			{
				token_info token;
				if (!p.load(p.to(), token) || token.owner != p.from())
					throw exception_ptr("logical_error", "from does not own the token");

				token_balance output;
				if (!p.load(token.owner, output))
					output.owner = token.owner;

				uint256 supply_delta = token.supply - value;
				if (supply_delta > token.supply)
					throw exception_ptr("logical_error", "token supply will underflow (" + token.supply.to_string() + " < " + value.to_string() + ")");

				uint256 to_delta = output.value - value;
				if (to_delta > output.value)
					throw exception_ptr("argument_error", "owner balance will underflow (" + output.value.to_string() + " < " + value.to_string() + ")");

				token.supply = supply_delta;
				output.value = to_delta;
				p.store(p.to(), token);
				p.store(output.owner, output);
				return output.value;
			}
			uint256 balance_of(program@ const p, const address & in owner)
			{
				token_balance output;
				if (!p.load(owner, output))
					output.owner = owner;
				return output.value;
			}
			token_info info(program@ const p)
			{
				token_info token;
				if (!p.load(p.to(), token))
					throw exception_ptr("logical_error", "token info not found");

				return token;
			});

			auto* deployment_ethereum1 = memory::init<transactions::deployment>();
			deployment_ethereum1->set_asset("ETH");
			deployment_ethereum1->set_program_calldata(token_program, { format::variable(1000000u) });
			deployment_ethereum1->sign_location(token_contract.secret_key);
			deployment_ethereum1->set_estimate_gas(std::string_view("0.00000001"));
			VI_PANIC(deployment_ethereum1->sign(user1.secret_key, user1_sequence++), "deployment not signed");
			transactions.push_back(deployment_ethereum1);

			ledger::wallet bridge_contract = ledger::wallet::from_seed(string("bridge") + string((char*)user1.secret_key, sizeof(user1.secret_key)));
			std::string_view bridge_program = VI_STRINGIFY(
			class token_balance
			{
				address owner;
				uint256 value = 0;
			}

			uint256 my_balance(program@ const p)
			{
				uint256 from_balance = 0;
				p.call("%s", "balance_of", p.from(), from_balance);
				return from_balance;
			});

			auto* deployment_ethereum2 = memory::init<transactions::deployment>();
			deployment_ethereum2->set_asset("ETH");
			deployment_ethereum2->set_program_calldata(stringify::text(bridge_program.data(), token_contract.get_address().c_str()), { });
			deployment_ethereum2->sign_location(bridge_contract.secret_key);
			deployment_ethereum2->set_estimate_gas(std::string_view("0.00000001"));
			VI_PANIC(deployment_ethereum2->sign(user1.secret_key, user1_sequence++), "deployment not signed");
			transactions.push_back(deployment_ethereum2);
		}
		static void invocations(vector<uptr<ledger::transaction>>& transactions, vector<account>& users)
		{
			auto& [user1, user1_sequence] = users[0];
			auto& [user2, user2_sequence] = users[1];
			ledger::wallet token_contract = ledger::wallet::from_seed(string("token") + string((char*)user1.secret_key, sizeof(user1.secret_key)));
			auto* invocation_ethereum1 = memory::init<transactions::invocation>();
			invocation_ethereum1->set_asset("ETH");
			invocation_ethereum1->set_calldata(token_contract.public_key_hash, "transfer", { format::variable(std::string_view((char*)user2.public_key_hash, sizeof(user2.public_key_hash))), format::variable(250000u) });
			invocation_ethereum1->set_estimate_gas(std::string_view("0.00000001"));
			VI_PANIC(invocation_ethereum1->sign(user1.secret_key, user1_sequence++), "invocation not signed");
			transactions.push_back(invocation_ethereum1);

			ledger::wallet bridge_contract = ledger::wallet::from_seed(string("bridge") + string((char*)user1.secret_key, sizeof(user1.secret_key)));
			auto* invocation_bitcoin = memory::init<transactions::invocation>();
			invocation_bitcoin->set_asset("BTC");
			invocation_bitcoin->set_calldata(bridge_contract.public_key_hash, "my_balance", { });
			invocation_bitcoin->set_estimate_gas(std::string_view("0.0000000005"));
			VI_PANIC(invocation_bitcoin->sign(user1.secret_key, user1_sequence++), "invocation not signed");
			transactions.push_back(invocation_bitcoin);
		}
		static void migrations_stage1(vector<uptr<ledger::transaction>>& transactions, vector<account>& users)
		{
			auto& [user1, user1_sequence] = users[0];
			auto& [user2, user2_sequence] = users[1];
			auto context = ledger::transaction_context();
			auto depository = context.get_account_depository(algorithm::asset::id_of("ETH"), user2.public_key_hash);
			if (!depository)
				return;

			auto* custodian_account_ethereum = memory::init<transactions::custodian_account>();
			custodian_account_ethereum->set_asset("ETH");
			custodian_account_ethereum->set_estimate_gas(decimal::zero());
			custodian_account_ethereum->set_wallet(&context, user1, user1.public_key_hash).expect("custodian address not deployed");
			VI_PANIC(custodian_account_ethereum->sign(user1.secret_key, user1_sequence++), "account not signed");
			transactions.push_back(custodian_account_ethereum);
		}
		static void migrations_stage2(vector<uptr<ledger::transaction>>& transactions, vector<account>& users)
		{
			auto& [user1, user1_sequence] = users[0];
			auto& [user2, user2_sequence] = users[1];
			auto context = ledger::transaction_context();
			auto depository = context.get_account_depository(algorithm::asset::id_of("ETH"), user2.public_key_hash);
			if (!depository)
				return;

			auto* depository_migration_ethereum = memory::init<transactions::depository_migration>();
			depository_migration_ethereum->set_asset("ETH");
			depository_migration_ethereum->set_estimate_gas(decimal::zero());
			depository_migration_ethereum->set_proposer(user1.public_key_hash, depository->custody);
			VI_PANIC(depository_migration_ethereum->sign(user2.secret_key, user2_sequence++), "depository migration not signed");
			transactions.push_back(depository_migration_ethereum);
		}
		static void withdrawals_stage1(vector<uptr<ledger::transaction>>& transactions, vector<account>& users)
		{
			auto& [user1, user1_sequence] = users[0];
			auto& [user2, user2_sequence] = users[1];
			auto context = ledger::transaction_context();
			auto* withdrawal_ethereum = memory::init<transactions::withdrawal>();
			withdrawal_ethereum->set_asset("ETH");
			withdrawal_ethereum->set_estimate_gas(decimal::zero());
			withdrawal_ethereum->set_to("0xCa0dfDdBb1cBD7B5A08E9173D9bbE5722138d4d5", context.get_account_balance(algorithm::asset::id_of("ETH"), user1.public_key_hash).expect("user balance not valid").get_balance());
			withdrawal_ethereum->set_proposer(user1.public_key_hash);
			VI_PANIC(withdrawal_ethereum->sign(user1.secret_key, user1_sequence++), "withdrawal not signed");
			transactions.push_back(withdrawal_ethereum);

			auto* withdrawal_ripple = memory::init<transactions::withdrawal>();
			withdrawal_ripple->set_asset("XRP");
			withdrawal_ripple->set_estimate_gas(decimal::zero());
			withdrawal_ripple->set_to("rUBqz2JiRCT3gYZBnm28y5ME7e5UpSm2ok", context.get_account_balance(algorithm::asset::id_of("XRP"), user1.public_key_hash).expect("user balance not valid").get_balance());
			withdrawal_ripple->set_proposer(user2.public_key_hash);
			VI_PANIC(withdrawal_ripple->sign(user1.secret_key, user1_sequence++), "withdrawal not signed");
			transactions.push_back(withdrawal_ripple);

			auto* withdrawal_bitcoin = memory::init<transactions::withdrawal>();
			withdrawal_bitcoin->set_asset("BTC");
			withdrawal_bitcoin->set_estimate_gas(decimal::zero());
			withdrawal_bitcoin->set_to("mmtubFoJvXrBuBUQFf1RrowXUbsiPDYnYS", context.get_account_balance(algorithm::asset::id_of("BTC"), user1.public_key_hash).expect("user balance not valid").get_balance());
			withdrawal_bitcoin->set_proposer(user2.public_key_hash);
			VI_PANIC(withdrawal_bitcoin->sign(user1.secret_key, user1_sequence++), "withdrawal not signed");
			transactions.push_back(withdrawal_bitcoin);
		}
		static void withdrawals_stage2(vector<uptr<ledger::transaction>>& transactions, vector<account>& users)
		{
			auto& [user1, user1_sequence] = users[0];
			auto& [user2, user2_sequence] = users[1];
			auto context = ledger::transaction_context();
			auto* withdrawal_ethereum = memory::init<transactions::withdrawal>();
			withdrawal_ethereum->set_asset("ETH");
			withdrawal_ethereum->set_estimate_gas(decimal::zero());
			withdrawal_ethereum->set_to("0x89a0181659bd280836A2d33F57e3B5Dfa1a823CE", context.get_account_balance(algorithm::asset::id_of("ETH"), user2.public_key_hash).expect("proposer balance not valid").get_balance());
			withdrawal_ethereum->set_proposer(user1.public_key_hash);
			VI_PANIC(withdrawal_ethereum->sign(user2.secret_key, user2_sequence++), "withdrawal not signed");
			transactions.push_back(withdrawal_ethereum);

			auto* withdrawal_ripple = memory::init<transactions::withdrawal>();
			withdrawal_ripple->set_asset("XRP");
			withdrawal_ripple->set_estimate_gas(decimal::zero());
			withdrawal_ripple->set_to("rJGb4etn9GSwNHYVu7dNMbdiVgzqxaTSUG", context.get_account_balance(algorithm::asset::id_of("XRP"), user2.public_key_hash).expect("proposer balance not valid").get_balance());
			withdrawal_ripple->set_proposer(user2.public_key_hash);
			VI_PANIC(withdrawal_ripple->sign(user2.secret_key, user2_sequence++), "withdrawal not signed");
			transactions.push_back(withdrawal_ripple);

			auto* withdrawal_bitcoin = memory::init<transactions::withdrawal>();
			withdrawal_bitcoin->set_asset("BTC");
			withdrawal_bitcoin->set_estimate_gas(decimal::zero());
			withdrawal_bitcoin->set_to("bcrt1p2w7gkghj7arrjy4c45kh7450458hr8dv9pu9576lx08uuh4je7eqgskm9v", context.get_account_balance(algorithm::asset::id_of("BTC"), user2.public_key_hash).expect("proposer balance not valid").get_balance());
			withdrawal_bitcoin->set_proposer(user2.public_key_hash);
			VI_PANIC(withdrawal_bitcoin->sign(user2.secret_key, user2_sequence++), "withdrawal not signed");
			transactions.push_back(withdrawal_bitcoin);
		}
		static void deallocations(vector<uptr<ledger::transaction>>& transactions, vector<account>& users)
		{
			auto& [user1, user1_sequence] = users[0];
			auto& [user2, user2_sequence] = users[1];
			auto chain = storages::chainstate(__func__);
			auto operations = chain.get_block_transactions_by_owner(std::numeric_limits<int64_t>::max(), user2.public_key_hash, 1, 0, 1024);
			if (!operations)
				return;

			for (auto& item : *operations)
			{
				if (item.transaction->as_type() != transactions::contribution_activation::as_instance_type())
					continue;

				ordered_set<string> parties;
				if (!item.transaction->recover_many(item.receipt, parties))
					continue;

				auto* contribution_deallocation = memory::init<transactions::contribution_deallocation>();
				contribution_deallocation->asset = item.transaction->asset;
				contribution_deallocation->set_estimate_gas(decimal::zero());
				if (parties.find(string((char*)user1.public_key_hash, sizeof(user1.public_key_hash))) == parties.end())
				{
					contribution_deallocation->set_witness(user2.secret_key, item.receipt.transaction_hash);
					VI_PANIC(contribution_deallocation->sign(user2.secret_key, user2_sequence++), "depository deallocation not signed");
				}
				else
				{
					contribution_deallocation->set_witness(user1.secret_key, item.receipt.transaction_hash);
					VI_PANIC(contribution_deallocation->sign(user1.secret_key, user1_sequence++), "depository deallocation not signed");
				}
				transactions.push_back(contribution_deallocation);
			}
		}
	};

public:
	/* 256bit integer serialization */
	static void generic_integer_serialization()
	{
		auto* term = console::get();
		term->capture_time();

		size_t samples = 1024 * 4;
		for (size_t i = 0; i < samples; i++)
		{
			uint256_t value = algorithm::hashing::hash256i(*crypto::random_bytes(32));

			uint8_t data1[32] = { 0 }; uint256_t value1 = 0;
			algorithm::encoding::decode_uint256(value, data1);
			algorithm::encoding::encode_uint256(data1, value1);
			VI_PANIC(value == value1, "uint256 serialization failed");
		}

		double time = term->get_captured_time();
		term->fwrite_line("uint256 serialization time: %.2f ms (cps: %.2f)", time, 1000.0 * (double)samples / time);
	}
	/* 256bit => decimal conversion */
	static void generic_integer_conversion()
	{
		auto* term = console::get();
		size_t samples = 100; double time = 0;
		for (size_t i = 0; i < samples; i++)
		{
			uint256_t number;
			algorithm::encoding::encode_uint256((uint8_t*)crypto::random_bytes(32)->data(), number);

			term->capture_time();
			decimal test = number.to_decimal();
			time += term->get_captured_time();
		}

		term->fwrite_line("uint256 to 256bit decimal conversion time: %.2f ms (cps: %.2f)", time, 1000.0 * (double)samples / time); time = 0;
		for (size_t i = 0; i < samples * 5; i++)
		{
			uint256_t number = math64u::random(0, std::numeric_limits<uint64_t>::max());
			term->capture_time();
			decimal test = number.to_decimal();
			time += term->get_captured_time();
		}

		term->fwrite_line("uint256 to 64bit decimal conversion time: %.2f ms (cps: %.2f)", time, 1000.0 * (double)samples / time); time = 0;
		for (size_t i = 0; i < samples * 5; i++)
		{
			uint256_t number = math32u::random(0, std::numeric_limits<uint32_t>::max());
			term->capture_time();
			decimal test = number.to_decimal();
			time += term->get_captured_time();
		}

		term->fwrite_line("uint256 to 32bit decimal conversion time: %.2f ms (cps: %.2f)", time, 1000.0 * (double)samples / time); time = 0;
		for (size_t i = 0; i < samples * 10; i++)
		{
			uint256_t number = math32u::random(0, std::numeric_limits<uint16_t>::max());
			term->capture_time();
			decimal test = number.to_decimal();
			time += term->get_captured_time();
		}

		term->fwrite_line("uint256 to 16bit decimal conversion time: %.2f ms (cps: %.2f)", time, 1000.0 * (double)samples / time); time = 0;
	}
	/* 256bit => decimal conversion */
	static void generic_message_serialization()
	{
		algorithm::pubkeyhash owner;
		algorithm::hashing::hash160((uint8_t*)"publickeyhash", 13, owner);
		uint64_t block_number = 1;
		uint64_t block_nonce = 1;

		uptr<schema> data = var::set::object();
		new_serialization_comparison<mediator::master_wallet>(*data);
		new_serialization_comparison<mediator::derived_verifying_wallet>(*data);
		new_serialization_comparison<mediator::derived_signing_wallet>(*data);
		new_serialization_comparison<mediator::incoming_transaction>(*data);
		new_serialization_comparison<mediator::outgoing_transaction>(*data);
		new_serialization_comparison<mediator::index_address>(*data);
		new_serialization_comparison<mediator::index_utxo>(*data);
		new_serialization_comparison<ledger::receipt>(*data);
		new_serialization_comparison<ledger::wallet>(*data);
		new_serialization_comparison<ledger::validator>(*data);
		new_serialization_comparison<ledger::block_transaction>(*data);
		new_serialization_comparison<ledger::block_header>(*data);
		new_serialization_comparison<ledger::block>(*data);
		new_serialization_comparison<ledger::block_proof>(*data, ledger::block_header(), (ledger::block_header*)nullptr);
		new_serialization_comparison<states::account_sequence>(*data, owner, block_number++, block_nonce++);
		new_serialization_comparison<states::account_work>(*data, owner, block_number++, block_nonce++);
		new_serialization_comparison<states::account_observer>(*data, owner, block_number++, block_nonce++);
		new_serialization_comparison<states::account_program>(*data, owner, block_number++, block_nonce++);
		new_serialization_comparison<states::account_storage>(*data, owner, block_number++, block_nonce++);
		new_serialization_comparison<states::account_reward>(*data, owner, block_number++, block_nonce++);
		new_serialization_comparison<states::account_derivation>(*data, owner, block_number++, block_nonce++);
		new_serialization_comparison<states::account_balance>(*data, owner, block_number++, block_nonce++);
		new_serialization_comparison<states::account_depository>(*data, owner, block_number++, block_nonce++);
		new_serialization_comparison<states::witness_program>(*data, block_number++, block_nonce++);
		new_serialization_comparison<states::witness_event>(*data, block_number++, block_nonce++);
		new_serialization_comparison<states::witness_address>(*data, owner, block_number++, block_nonce++);
		new_serialization_comparison<states::witness_transaction>(*data, block_number++, block_nonce++);
		new_serialization_comparison<transactions::transfer>(*data);
		new_serialization_comparison<transactions::omnitransfer>(*data);
		new_serialization_comparison<transactions::deployment>(*data);
		new_serialization_comparison<transactions::invocation>(*data);
		new_serialization_comparison<transactions::withdrawal>(*data);
		new_serialization_comparison<transactions::rollup>(*data);
		new_serialization_comparison<transactions::commitment>(*data);
		new_serialization_comparison<transactions::incoming_claim>(*data);
		new_serialization_comparison<transactions::outgoing_claim>(*data);
		new_serialization_comparison<transactions::address_account>(*data);
		new_serialization_comparison<transactions::pubkey_account>(*data);
		new_serialization_comparison<transactions::delegation_account>(*data);
		new_serialization_comparison<transactions::custodian_account>(*data);
		new_serialization_comparison<transactions::contribution_allocation>(*data);
		new_serialization_comparison<transactions::contribution_selection>(*data);
		new_serialization_comparison<transactions::contribution_activation>(*data);
		new_serialization_comparison<transactions::contribution_deallocation>(*data);
		new_serialization_comparison<transactions::contribution_deselection>(*data);
		new_serialization_comparison<transactions::contribution_deactivation>(*data);
		new_serialization_comparison<transactions::depository_adjustment>(*data);
		new_serialization_comparison<transactions::contribution_selection>(*data);
		new_serialization_comparison<transactions::depository_migration>(*data);

		auto* term = console::get();
		term->jwrite_line(*data);
	}
	/* prove and verify nakamoto POW */
	static void cryptography_nakamoto()
	{
		auto* term = console::get();
		term->capture_time();

		auto message = "Hello, world!";
		uint256_t target = uint256_t(1) << uint256_t(244);
		uint256_t nonce = 0;
		while (true)
		{
			auto solution = algorithm::nakamoto::evaluate(nonce, message);
			if (algorithm::nakamoto::verify(nonce, message, target, solution))
			{
				uptr<schema> data = var::set::object();
				data->set("solution", algorithm::encoding::serialize_uint256(solution));
				data->set("nonce", algorithm::encoding::serialize_uint256(nonce));
				data->set("milliseconds", var::set::number(term->get_captured_time()));

				term->jwrite_line(*data);
				break;
			}
			else
				++nonce;
		}
	}
	/* prove and verify wesolowski VDF signature */
	static void cryptography_wesolowski()
	{
		auto* term = console::get();
		term->capture_time();

		auto message = "Hello, world!";
		auto alg = algorithm::wesolowski::parameters(); alg.pow *= 12;
		auto signature = algorithm::wesolowski::evaluate(alg, message);
		bool proven = algorithm::wesolowski::verify(alg, message, signature);
		uptr<schema> data = var::set::object();
		data->set("solution", var::string(format::util::encode_0xhex(signature)));
		data->set("milliseconds", var::set::number(term->get_captured_time()));

		term->jwrite_line(*data);
		VI_PANIC(proven, "wesolowki proof is not valid");
	}
	/* cryptographic signatures */
	static void cryptography_signatures()
	{
		auto* term = console::get();
		string mnemonic = "chimney clerk liberty defense gesture risk disorder switch raven chapter document admit win swing forward please clerk vague online coil material tone sibling intact";
		algorithm::seckey secret_key;
		algorithm::pubkey public_key;
		algorithm::pubkeyhash public_key_hash;
		algorithm::signing::derive_secret_key_from_mnemonic(mnemonic, secret_key);
		algorithm::signing::derive_public_key(secret_key, public_key);
		algorithm::signing::derive_public_key_hash(public_key, public_key_hash);

		string encoded_secret_key, encoded_public_key, encoded_public_key_hash;
		algorithm::signing::encode_secret_key(secret_key, encoded_secret_key);
		algorithm::signing::encode_public_key(public_key, encoded_public_key);
		algorithm::signing::encode_address(public_key_hash, encoded_public_key_hash);

		string message = "Hello, world!";
		uint256_t message_hash = algorithm::hashing::hash256i(message);
		string encoded_message_hash = algorithm::encoding::encode_0xhex256(message_hash);
		algorithm::recsighash message_signature;
		algorithm::pubkey recover_public_key;
		algorithm::pubkeyhash recover_public_key_hash;
		bool verifies = algorithm::signing::sign(message_hash, secret_key, message_signature) && algorithm::signing::verify(message_hash, public_key, message_signature);
		bool recovers_public_key = algorithm::signing::recover(message_hash, recover_public_key, message_signature);
		bool recovers_public_key_hash = algorithm::signing::recover_hash(message_hash, recover_public_key_hash, message_signature);
		string encoded_message_signature = format::util::encode_0xhex(std::string_view((char*)message_signature, sizeof(message_signature)));
		string encoded_recover_public_key, encoded_recover_public_key_hash;
		algorithm::signing::encode_public_key(recover_public_key, encoded_recover_public_key);
		algorithm::signing::encode_address(recover_public_key_hash, encoded_recover_public_key_hash);

		auto info = uptr<schema>(var::set::object());
		info->set("mnemonic", var::string(mnemonic));
		info->set("mnemonic_test", var::string(algorithm::signing::verify_mnemonic(mnemonic) ? "passed" : "failed"));
		info->set("secret_key", var::string(encoded_secret_key));
		info->set("secret_key_test", var::string(algorithm::signing::verify_secret_key(secret_key) ? "passed" : "failed"));
		info->set("public_key", var::string(encoded_public_key));
		info->set("public_key_test", var::string(algorithm::signing::verify_public_key(public_key) ? "passed" : "failed"));
		info->set("address", var::string(encoded_public_key_hash));
		info->set("address_test", var::string(algorithm::signing::verify_address(encoded_public_key_hash) ? "passed" : "failed"));
		info->set("message", var::string(message));
		info->set("message_hash", var::string(encoded_message_hash));
		info->set("signature", var::string(encoded_message_signature));
		info->set("signature_test", var::string(verifies ? "passed" : "failed"));
		info->set("recover_public_key", var::string(encoded_recover_public_key));
		info->set("recover_public_key_test", var::string(recovers_public_key && encoded_recover_public_key == encoded_public_key ? "passed" : "failed"));
		info->set("recover_address", var::string(encoded_recover_public_key_hash));
		info->set("recover_address_test", var::string(recovers_public_key_hash && encoded_recover_public_key_hash == encoded_public_key_hash ? "passed" : "failed"));

		term->jwrite_line(*info);
		VI_PANIC(schema::to_json(*info).find("failed") == std::string::npos, "cryptographic error");
	}
	/* wallet cryptography */
	static void cryptography_wallet()
	{
		auto* term = console::get();
		auto wallet = ledger::wallet::from_seed();
		auto wallet_info = wallet.as_schema();
		wallet_info->set("secret_key_test", var::string(algorithm::signing::verify_secret_key(wallet.secret_key) ? "passed" : "failed"));
		wallet_info->set("public_key_test", var::string(algorithm::signing::verify_public_key(wallet.public_key) ? "passed" : "failed"));
		wallet_info->set("address_test", var::string(algorithm::signing::verify_address(wallet.get_address()) ? "passed" : "failed"));

		term->jwrite_line(*wallet_info);
		VI_PANIC(schema::to_json(*wallet_info).find("failed") == std::string::npos, "cryptographic error");
	}
	/* shared wallet cryptography */
	static void cryptography_wallet_sharing()
	{
		auto* term = console::get();
		auto* server = nss::server_node::get();
		for (auto& id : server->get_assets())
		{
			auto alg = server->get_chainparams(id)->composition;
			string hash1 = *crypto::hash_raw(digests::SHA256(), "seed1");
			string hash2 = *crypto::hash_raw(digests::SHA256(), "seed2");
			string bytes1 = *crypto::random_bytes(64);
			string bytes2 = *crypto::random_bytes(64);
			string message = "Hello, world!";
			size_t public_key_size = 0;
			size_t secret_key_size = 0;
			algorithm::composition::cpubkey public_key;
			algorithm::composition::cseckey secret_key;
			algorithm::composition::cseed seed1, seed2;
			algorithm::composition::cseckey secret_key1, secret_key2;
			algorithm::composition::cpubkey public_key1, public_key2;
			algorithm::composition::convert_to_secret_seed((uint8_t*)hash1.data(), bytes1, seed1);
			algorithm::composition::convert_to_secret_seed((uint8_t*)hash2.data(), bytes2, seed2);
			algorithm::composition::derive_keypair(alg, seed1, secret_key1, public_key1);
			algorithm::composition::derive_keypair(alg, seed2, secret_key2, public_key2);
			algorithm::composition::derive_public_key(alg, public_key1, secret_key2, public_key, &public_key_size);
			algorithm::composition::derive_secret_key(alg, secret_key1, secret_key2, secret_key, &secret_key_size);
			auto signing_wallet = server->new_signing_wallet(id, secret_box::view(std::string_view((char*)secret_key, secret_key_size))).expect("wallet derivation failed");
			auto verifying_wallet = server->new_verifying_wallet(id, std::string_view((char*)public_key, public_key_size)).expect("wallet derivation failed");
			auto signature = server->sign_message(id, message, signing_wallet.signing_key);
			auto verification = signature ? server->verify_message(id, message, signing_wallet.verifying_key, *signature) : expects_lr<void>(layer_exception("signature generation failed"));

			uptr<schema> data = var::set::object();
			data->set("asset", algorithm::asset::serialize(id));
			data->set("algorithm", var::string(alg == algorithm::composition::type::SECP256K1 ? "secp256k1" : "ed25519"));
			data->set("seed_hash_1", var::string(format::util::encode_0xhex(hash1)));
			data->set("seed_hash_2", var::string(format::util::encode_0xhex(hash2)));
			data->set("seed_bytes_1", var::string(format::util::encode_0xhex(bytes1)));
			data->set("seed_bytes_2", var::string(format::util::encode_0xhex(bytes2)));
			data->set("secret_key_share_1", var::string(format::util::encode_0xhex(std::string_view((char*)secret_key1, sizeof(secret_key1)))));
			data->set("secret_key_share_2", var::string(format::util::encode_0xhex(std::string_view((char*)secret_key2, sizeof(secret_key2)))));
			data->set("secret_key_composition", var::string(format::util::encode_0xhex(std::string_view((char*)secret_key, secret_key_size))));
			data->set("public_key_composition", var::string(format::util::encode_0xhex(std::string_view((char*)public_key, public_key_size))));
			data->set("keypair_composition", var::string(signing_wallet.addresses.begin()->second == verifying_wallet.addresses.begin()->second ? "passed" : "failed"));
			data->set("signing_wallet_secret_key", var::string(signing_wallet.signing_key.heap()));
			data->set("signing_wallet_public_key", var::string(signing_wallet.verifying_key));
			data->set("signing_wallet_address", var::string(signing_wallet.addresses.begin()->second));
			data->set("verifying_wallet_public_key", var::string(verifying_wallet.verifying_key));
			data->set("verifying_wallet_address", var::string(verifying_wallet.addresses.begin()->second));
			data->set("signature_payload", var::string((signature ? *signature : signature.error().message()) + string(signature ? "" : " (failed)")));
			data->set("signature_verification", var::string(string(verification ? "passed" : verification.error().what()) + string(verification ? "" : " (failed)")));
			data->set("blob_payload", var::string(message));

			term->jwrite_line(*data);
			VI_PANIC(schema::to_json(*data).find("failed") == std::string::npos, "cryptographic error");
		}
	}
	/* wallet encryption cryptography */
	static void cryptography_wallet_messaging()
	{
		auto* term = console::get();
		auto user1 = ledger::wallet::from_seed();
		auto user2 = ledger::wallet::from_seed();
		auto nonce1 = uint256_t(110);
		auto nonce2 = uint256_t(220);

		algorithm::seckey cipher_secret_key1, cipher_secret_key2;
		algorithm::pubkey cipher_public_key1, cipher_public_key2;
		algorithm::signing::derive_cipher_keypair(user1.secret_key, nonce1, cipher_secret_key1, cipher_public_key1);
		algorithm::signing::derive_cipher_keypair(user2.secret_key, nonce2, cipher_secret_key2, cipher_public_key2);

		auto message_from_user1 = "Hello, alice!";
		auto message_from_user2 = "Hello, bob!";
		auto ciphertext1 = user1.seal_message(message_from_user1, cipher_public_key2, *crypto::random_bytes(64));
		auto plaintext1 = ciphertext1 ? user2.open_message(nonce2, *ciphertext1) : option<string>(optional::none);
		auto ciphertext2 = user2.seal_message(message_from_user2, cipher_public_key1, *crypto::random_bytes(64));
		auto plaintext2 = ciphertext2 ? user1.open_message(nonce1, *ciphertext2) : option<string>(optional::none);

		uptr<schema> data = var::set::object();
		auto* user1_wallet_data = data->set("user1_wallet", user1.as_schema().reset());
		auto* user1_wallet_message_data = user1_wallet_data->set("message");
		user1_wallet_message_data->set("cipher_nonce", algorithm::encoding::serialize_uint256(nonce1));
		user1_wallet_message_data->set("cipher_secret_key", var::string(format::util::encode_0xhex(std::string_view((char*)cipher_secret_key1, sizeof(cipher_secret_key1)))));
		user1_wallet_message_data->set("cipher_public_key", var::string(format::util::encode_0xhex(std::string_view((char*)cipher_public_key1, sizeof(cipher_public_key1)))));
		user1_wallet_message_data->set("ciphertext_to_user2_wallet", var::string(ciphertext1 ? format::util::encode_0xhex(*ciphertext1).c_str() : "** encryption failed **"));
		user1_wallet_message_data->set("plaintext_from_user2_wallet", var::string(plaintext2 ? plaintext2->c_str() : "** decryption failed **"));
		auto* user2_wallet_data = data->set("user2_wallet", user2.as_schema().reset());
		auto* user2_wallet_message_data = user2_wallet_data->set("message");
		user2_wallet_message_data->set("cipher_nonce", algorithm::encoding::serialize_uint256(nonce2));
		user2_wallet_message_data->set("cipher_secret_key", var::string(format::util::encode_0xhex(std::string_view((char*)cipher_secret_key2, sizeof(cipher_secret_key2)))));
		user2_wallet_message_data->set("cipher_public_key", var::string(format::util::encode_0xhex(std::string_view((char*)cipher_public_key2, sizeof(cipher_public_key2)))));
		user2_wallet_message_data->set("ciphertext_to_user2_wallet", var::string(ciphertext2 ? format::util::encode_0xhex(*ciphertext2).c_str() : "** encryption failed **"));
		user2_wallet_message_data->set("plaintext_from_user2_wallet", var::string(plaintext1 ? plaintext1->c_str() : "** decryption failed **"));

		term->jwrite_line(*data);
		VI_PANIC(schema::to_json(*data).find("failed") == std::string::npos, "cryptographic error");
	}
	/* transaction cryptography */
	static void cryptography_transaction()
	{
		auto* term = console::get();
		auto wallet = ledger::wallet::from_seed();
		vector<uptr<ledger::transaction>> transactions;
		vector<account> users =
		{
			account(wallet, 1),
			account(ledger::wallet::from_seed(), 1)
		};
		generators::transfers(transactions, users);
		auto& tx = *(transactions::transfer*)*transactions.back();
		auto tx_blob = tx.as_message().data;
		auto tx_body = format::stream(tx_blob);
		auto tx_copy = uptr<ledger::transaction>(transactions::resolver::init(messages::authentic::resolve_type(tx_body).otherwise(0)));
		auto tx_info = tx.as_schema();
		algorithm::pubkeyhash recover_public_key_hash = { 0 };
		tx_info->set("recovery_test", var::string(tx.recover_hash(recover_public_key_hash) && !memcmp(wallet.public_key_hash, recover_public_key_hash, sizeof(recover_public_key_hash)) ? "passed" : "failed"));
		tx_info->set("verification_test", var::string(tx.verify(wallet.public_key) ? "passed" : "failed"));
		tx_info->set("serialization_test", var::string(tx_copy && tx_copy->load(tx_body) && tx_copy->as_message().data == tx_blob ? "passed" : "failed"));
		tx_info->set("raw_data_test", var::string(format::util::encode_0xhex(tx_blob)));

		auto stream = tx.as_message();
		format::variables vars;
		format::variables_util::deserialize_flat_from(stream, &vars);
		tx_info->set("var_data_test", format::variables_util::serialize(vars));
		tx_info->set("asset_test", algorithm::asset::serialize(algorithm::asset::id_of("ETH", "USDT", "0xdAC17F958D2ee523a2206206994597C13D831ec7")));

		term->jwrite_line(*tx_info);
		VI_PANIC(schema::to_json(*tx_info).find("failed") == std::string::npos, "cryptographic error");
	}
	/* merkle tree cryptography */
	static void cryptography_merkle_tree()
	{
		auto* term = console::get();
		const size_t hashes = 16;
		uint256_t prev = algorithm::hashing::hash256i(*crypto::random_bytes(16));
		uint256_t next = algorithm::hashing::hash256i(*crypto::random_bytes(16));
		algorithm::merkle_tree tree = prev;
		for (size_t i = 0; i < hashes; i++)
		{
			uint8_t hash[32];
			algorithm::encoding::decode_uint256(next, hash);

			tree.push(next);
			next = algorithm::hashing::hash256i(std::string_view((char*)hash, sizeof(hash)));
		}

		auto& nodes = tree.get_tree();
		uint256_t target = nodes[math64u::random(1, hashes + 1)];
		term->fwrite_line("merkle tree (nodes = %i, target = %s):", (int)nodes.size(), algorithm::encoding::encode_0xhex256(target).c_str());
		for (size_t i = 0; i < nodes.size(); i++)
			term->write_line("  " + algorithm::encoding::encode_0xhex256(nodes[i]));

		auto path = tree.calculate_path(target);
		auto proposed_root = path.calculate_root(target);
		auto actual_root = tree.calculate_root();
		auto& branch = path.get_branch();
		branch.insert(branch.begin(), target);
		branch.push_back(proposed_root);

		term->fwrite_line("merkle tree path (index in tree = %i, nodes = %i):", (int)path.get_index(), (int)branch.size());
		for (size_t i = 0; i < branch.size(); i++)
			term->write_line("  " + algorithm::encoding::encode_0xhex256(branch[i]));

		term->fwrite_line("merkle tree (complexity = %i, nodes = %i, verification = %s):", (int)tree.get_complexity(), (int)nodes.size(), proposed_root == actual_root ? "passed" : "failed");
		for (size_t i = 0; i < nodes.size(); i++)
		{
			auto it = std::find(branch.begin(), branch.end(), nodes[i]);
			if (it != branch.end())
			{
				size_t depth = it - branch.begin() + 1;
				term->write_line("  " + string(depth, '>') + string(1 + branch.size() - depth, ' ') + algorithm::encoding::encode_0xhex256(nodes[i]));
			}
			else
				term->write_line("  " + string(1 + branch.size(), ' ') + algorithm::encoding::encode_0xhex256(nodes[i]));
		}
		VI_PANIC(proposed_root == actual_root, "cryptographic error");
	}
	/* oracle wallets cryptography */
	static void cryptography_multichain()
	{
		auto* term = console::get();
		auto user = ledger::wallet::from_seed("0000000");
		for (auto& master_wallet : nss::server_node::get()->get_wallets(user.secret_key))
		{
			auto asset = algorithm::asset::id_of(master_wallet.first);
			auto signer = nss::server_node::get()->new_signing_wallet(asset, master_wallet.second, 0);
			auto wallet = uptr<schema>(var::set::object());
			wallet->set("asset", algorithm::asset::serialize(asset));
			wallet->set("master", master_wallet.second.as_schema().reset());
			wallet->set("child", signer ? signer->as_schema().reset() : var::set::string("failed"));

			term->jwrite_line(*wallet);
			VI_PANIC(schema::to_json(*wallet).find("failed") == std::string::npos, "cryptographic error");
		}
	}
	/* blockchain containing all transaction types (zero balance accounts, valid regtest chain) */
	static void blockchain_full_coverage(vector<account>* userdata)
	{
		auto* term = console::get();
		auto& params = protocol::change();
		auto path = params.database.location();
		params.database.reset();
		os::directory::remove(path);
		storages::chainstate(__func__).clear_indexer_cache();

		uptr<schema> data = userdata ? nullptr : var::set::array();
		vector<account> users =
		{
			account(ledger::wallet::from_seed("000001"), 0),
			account(ledger::wallet::from_seed("000000"), 0),
			account(ledger::wallet::from_seed("000002"), 0)
		};
		TEST_BLOCK(&generators::commitments, "0xa004030f97a9a1bacf2f1d2c8304ae7fd27e3cc262418406e27045e2c1bff232", 1);
		TEST_BLOCK(&generators::adjustments, "0xcf86a27ab142a00ea12300fee506cac8078686f69e95deb24abc42d3bcb63dc9", 2);
		TEST_BLOCK(&generators::address_accounts, "0x71603c6f7a41212ab949d12871abc9ec2bd4f9eddd1704a620bb39a626d1462d", 3);
		TEST_BLOCK(&generators::pubkey_accounts, "0x08a5c556dda4de4519aa4ac324bea1a31ba11d9a974fd17e0f2e86781e30cac0", 4);
		TEST_BLOCK(std::bind(&generators::commitment_online, std::placeholders::_1, std::placeholders::_2, 2), "0x264bb7610dbb3fb9481e3e8c7717211bc1f6a0e05d7f6f84badfdbe9cb23d5a8", 5);
		TEST_BLOCK(&generators::allocations, "0xb289f4f1bdbe169140f7db7c0045447e118159a4e9ed11d9ebc897dbd0e6b102", 6);
		TEST_BLOCK(&generators::contributions, "0x491e9938f9dc7ff87b986fe53458afb3e3c815944a80eedad6b0874e60844d45", 9);
		TEST_BLOCK(&generators::delegated_custodian_accounts, "0x027629b91cabd1f0e140cde6a82267745e05f8421f7023f93203305a55878ea7", 10);
		TEST_BLOCK(&generators::claims, "0x8d549e9979f87cb59649bd5e44199ad235e84a455da6ebafd0217dae2e74477b", 12);
		TEST_BLOCK(&generators::transfers, "0xdde5a6ff371833d362252dcec5601e2566e11bcb797236066b34676b57c86602", 13);
		TEST_BLOCK(&generators::rollups, "0x861fe39d75e4e7eeb830cf44b9646e05bdd0ecd714c96acaee1191f86f5c6bdd", 14);
		TEST_BLOCK(&generators::deployments, "0x5dfc2d0f8b753c840624c1f55bce036f19ff6bfa0e27e36800f1031d077670da", 15);
		TEST_BLOCK(&generators::invocations, "0x2674f184a2b8aacdcf2fe134bb300762558fe69da1b405475140bf40b3247651", 16);
		TEST_BLOCK(&generators::migrations_stage1, "0x2222456261936d0127db59a94b26c44ddd13a2d6e278ed38ec2cfe7cc2c4e781", 17);
		TEST_BLOCK(&generators::migrations_stage2, "0x99508d454a888a73637e963c150f9e3706dbedbf353e8739d8d4563434392c20", 18);
		TEST_BLOCK(&generators::withdrawals_stage1, "0xf6a03921845ffeb31dca9a2e03c41293b67f37a23af49174fdfa38c12703f46d", 20);
		TEST_BLOCK(&generators::withdrawals_stage2, "0xe1986c23bf4e5f26481e67877c09218f1718951e12619b68c0f00e78cd5fa0c1", 22);
		TEST_BLOCK(std::bind(&generators::commitment_offline, std::placeholders::_1, std::placeholders::_2, 2), "0x511a0f1363492b28423df477cd0a4acea6d54940979e309903c3cfd9e2d0d0e7", 24);
		TEST_BLOCK(&generators::deallocations, "0x01f559d61b89b24b1ffa17865cebb8e392fe4fa65ef5176e4dd8977a05bbaf70", 25);
		if (userdata != nullptr)
			*userdata = std::move(users);
		else
			term->jwrite_line(*data);
	}
	/* blockchain containing some transaction types (non-zero balance accounts, valid regtest chain) */
	static void blockchain_partial_coverage(vector<account>* userdata)
	{
		auto* term = console::get();
		auto& params = protocol::change();
		auto path = params.database.location();
		params.database.reset();
		os::directory::remove(path);
		storages::chainstate(__func__).clear_indexer_cache();

		uptr<schema> data = userdata ? nullptr : var::set::array();
		vector<account> users =
		{
			account(ledger::wallet::from_seed("000000"), 0),
			account(ledger::wallet::from_seed("000001"), 0)
		};
		TEST_BLOCK(&generators::commitments, "0x80c0c8bedd1cf81dbf74b17fb3308fcd807c586546e4b9096b4f90484dec4e59", 1);
		TEST_BLOCK(&generators::adjustments, "0x0cef756f9bd46b9c7a5601c8cf91ba95ae343ddc198850226eff42b29b874191", 2);
		TEST_BLOCK(&generators::address_accounts, "0x9a56732df9b8c35cef0d634ac0bde7aab76198d31481d54f3da68dccaf82853d", 3);
		TEST_BLOCK(&generators::delegated_custodian_accounts, "0x99fb50ec6ed8a55576a4aed08b82a01731b09fb1bbbf8c8376db21240b4694cc", 4);
		TEST_BLOCK(&generators::claims, "0xb1cbc332b44acd8eabb6b9200ac06d4710d5a89a4b90e8c0e0a71439cee84fb0", 6);
		TEST_BLOCK(&generators::transfers, "0x54f38a05ab0dd861c9e868ef73c5334a00d019e6a7e23a923762200d55dec3e4", 7);
		TEST_BLOCK(&generators::rollups, "0x4741bd18f9e64d4509eaef3d2d16299b2849a28d8ba4ac6e4308681aaf8ec434", 8);
		TEST_BLOCK(std::bind(&generators::commitment_offline, std::placeholders::_1, std::placeholders::_2, 0), "0xd8ad0f7c68f3d90b1904a9e934201351ce3b0519c9f184ace0b4d37eafc6f86a", 9);
		TEST_BLOCK(std::bind(&generators::transfer_to_wallet, std::placeholders::_1, std::placeholders::_2, 0, algorithm::asset::id_of("BTC"), "tcrt1xrzy5qh6vs7phqnrft5se2sps8wyvr4u8tphzwl", 0.1), "0xe290d4c47fa71af8caf7f8b5a56c493baff2cab06c9e70a8cdc94d98fd54b45b", 10);
		if (userdata != nullptr)
			*userdata = std::move(users);
		else
			term->jwrite_line(*data);
	}
	/* verify current blockchain */
	static void blockchain_verification()
	{
		auto* term = console::get();
		auto chain = storages::chainstate(__func__);
		VI_PANIC(!chain.get_checkpoint_block_number().otherwise(0), "blockchain cannot be validated without re-executing entire blockchain");

		uint64_t current_number = 1;
		uptr<schema> data = var::set::array();
		auto parent_block = chain.get_block_header_by_number(current_number > 0 ? current_number - 1 : 0);
		while (true)
		{
			auto next = chain.get_block_by_number(current_number++);
			if (!next)
				break;

			auto* result = data->push(var::set::object());
			result->set("block_number", algorithm::encoding::serialize_uint256(next->number));
			result->set("block_hash", var::string(algorithm::encoding::encode_0xhex256(next->as_hash())));

			auto validation = next->validate(parent_block.address());
			if (!validation)
			{
				result->set("status", var::string("block validation test failed"));
				result->set("detail", var::string(validation.error().message()));
				break;
			}

			auto proof = next->as_proof(parent_block.address());
			for (auto& tx : next->transactions)
			{
				if (!proof.has_transaction(tx.receipt.transaction_hash))
				{
					result->set("transaction_hash", var::string(algorithm::encoding::encode_0xhex256(tx.receipt.transaction_hash)));
					result->set("status", var::string("transaction merkle test failed"));
					goto stop_verification;
				}
				else if (!proof.has_receipt(tx.receipt.as_hash()))
				{
					result->set("transaction_hash", var::string(algorithm::encoding::encode_0xhex256(tx.receipt.transaction_hash)));
					result->set("status", var::string("receipt merkle test failed"));
					goto stop_verification;
				}
			}

			size_t state_index = 0;
			for (auto& state : next->states.at(ledger::work_commitment::finalized))
			{
				uint256_t hash = state.second->as_hash();
				if (!proof.has_state(hash))
				{
					result->set("state_hash", var::string(algorithm::encoding::encode_0xhex256(hash)));
					result->set("status", var::string("state merkle test failed"));
					goto stop_verification;
				}
			}

			result->set("status", var::string("passed"));
			parent_block = *next;
			if (data->size() > 32)
			{
				term->jwrite_line(*data);
				data->clear();
			}
		}
	stop_verification:
		term->jwrite_line(*data);
		VI_PANIC(schema::to_json(*data).find("failed") == std::string::npos, "cryptographic error");
	}
	/* gas estimation */
	static void blockchain_gas_estimation()
	{
		auto* term = console::get();
		term->capture_time();

		algorithm::seckey from;
		crypto::fill_random_bytes(from, sizeof(from));

		algorithm::pubkeyhash to;
		crypto::fill_random_bytes(to, sizeof(to));

		uptr<transactions::transfer> transaction = memory::init<transactions::transfer>();
		transaction->set_asset("BTC");
		transaction->set_to(to, mathd::random());
		transaction->sign(from, 1, decimal::zero());

		uint256_t estimate_gas_limit = transaction->get_gas_estimate();
		uint256_t optimal_gas_limit = transaction->gas_limit;
		uint256_t block_gas_limit = ledger::block::get_gas_limit();
		uptr<schema> data = var::set::object();
		data->set("estimate_gas_limit", algorithm::encoding::serialize_uint256(estimate_gas_limit));
		data->set("optimal_gas_limit", algorithm::encoding::serialize_uint256(optimal_gas_limit));
		data->set("block_gas_limit", algorithm::encoding::serialize_uint256(block_gas_limit));
		term->jwrite_line(*data);
	}

public:
	template <typename t, typename... args>
	static void new_serialization_comparison(schema* data, args... arguments)
	{
		t instance = t(arguments...); format::stream message;
		VI_PANIC(instance.store(&message), "failed to store a message");

		t instance_copy = t(arguments...);
		VI_PANIC(instance_copy.load(message.rewind()), "failed to load a message");

		format::stream message_copy;
		VI_PANIC(instance_copy.store(&message_copy), "failed to store a message");
		VI_PANIC(message_copy.data == message.data, "serialization inconsistency found");

		data->set(t::as_instance_typename(), var::string(algorithm::encoding::encode_0xhex256(message.hash())));
	}
	static ledger::block new_block_from_generator(schema* results, vector<account>& users, std::function<void(vector<uptr<ledger::transaction>>&, vector<account>&)>&& test_case, const std::string_view& test_case_call, const std::string_view& state_root_hash, uint64_t block_number)
	{
		for (auto& user : users)
			user.sequence = user.wallet.get_latest_sequence().otherwise(1);

		vector<uptr<ledger::transaction>> transactions;
		test_case(transactions, users);

		auto block = new_block_from_list(results, users, std::move(transactions));
		auto hash = algorithm::encoding::encode_0xhex256(block.state_root);
		if (results != nullptr)
			console::get()->fwrite_line("TEST_BLOCK(%s, \"%s\", %" PRIu64 ");", test_case_call.data(), hash.c_str(), block.number);

		VI_PANIC(state_root_hash.empty() || state_root_hash == hash, "block state root deviation");
		VI_PANIC(!block_number || block_number == block.number, "block number deviation");
		return block;
	}
	static ledger::block new_block_from_list(schema* results, vector<account>& users, vector<uptr<ledger::transaction>>&& transactions)
	{
		ledger::evaluation_context environment;
		uint64_t priority = std::numeric_limits<uint64_t>::max();
		for (auto& user : users)
		{
			priority = environment.priority(user.wallet.public_key_hash, user.wallet.secret_key).otherwise(std::numeric_limits<uint64_t>::max());
			if (!priority)
				break;
		}

		VI_PANIC(priority == 0, "block proposal not allowed");
		for (auto& transaction : transactions)
		{
			if (transaction->get_type() != ledger::transaction_level::aggregation)
				continue;

			algorithm::pubkeyhash user;
			VI_PANIC(transaction->recover_hash(user), "transaction not recoverable");
			for (auto& [attestation_user, attestation_user_sequence] : users)
			{
				if (memcmp(attestation_user.public_key_hash, user, sizeof(user)) != 0)
					VI_PANIC(((ledger::aggregation_transaction*)*transaction)->attestate(attestation_user.secret_key), "transaction not attested");
			}
			transaction->gas_limit = ledger::transaction_context::calculate_tx_gas(*transaction).otherwise(transaction->gas_limit);
		}

		if (!environment.apply(std::move(transactions)))
			VI_PANIC(false, "empty block not allowed");

		string errors;
		auto evaluation = environment.evaluate(&errors);
		if (!errors.empty())
			VI_PANIC(false, "block evaluation error: %s", errors.c_str());

		auto proposal = std::move(evaluation.expect("block evaluation failed"));
		environment.solve(proposal).expect("block solution failed");
		if (results != nullptr)
			environment.verify(proposal).expect("block verification failed");

		transactions = vector<uptr<ledger::transaction>>();
		proposal.checkpoint().expect("block checkpoint failed");
		if (results != nullptr)
			results->push(proposal.as_schema().reset());

		vector<ledger::block_dispatch> dispatches;
		for (auto& [user, user_sequence] : users)
		{
			auto user_dispatch = proposal.dispatch_sync(user);
			if (user_dispatch && !user_dispatch->outputs.empty())
			{
				user_sequence = user.get_latest_sequence().otherwise(1);
				for (auto& transaction : user_dispatch->outputs)
				{
					if (transaction->get_type() == ledger::transaction_level::aggregation)
					{
						VI_PANIC(transaction->sign(user.secret_key), "dispatch transaction not signed");
						for (auto& [attestation_user, attestation_user_sequence] : users)
						{
							if (memcmp(attestation_user.public_key_hash, user.public_key_hash, sizeof(user.public_key_hash)) != 0)
								VI_PANIC(((ledger::aggregation_transaction*)*transaction)->attestate(attestation_user.secret_key), "dispatch transaction not attested");
						}
						transaction->gas_limit = ledger::transaction_context::calculate_tx_gas(*transaction).otherwise(transaction->gas_limit);
					}
					else
						VI_PANIC(transaction->sign(user.secret_key, user_sequence++, decimal::zero()), "dispatch transaction not signed");
				}
				transactions.insert(transactions.end(), std::make_move_iterator(user_dispatch->outputs.begin()), std::make_move_iterator(user_dispatch->outputs.end()));
				dispatches.push_back(std::move(*user_dispatch));
			}

			if (user_dispatch && !user_dispatch->errors.empty())
			{
				for (auto& transaction : user_dispatch->errors)
					VI_PANIC(false, "%s", transaction.second.c_str());
			}
		}

		for (auto& dispatch : dispatches)
			dispatch.checkpoint().expect("dispatch checkpoint failed");

		if (!transactions.empty())
			new_block_from_list(results, users, std::move(transactions));
		return proposal;
	}
};

class apps
{
public:
	/* nss, nds, p2p, rpc nodes */
	static int consensus(int argc, char* argv[])
	{
		VI_PANIC(argc > 1, "config path argument is required");
		vitex::runtime scope;
		std::string_view config = argv[1];
		std::string_view number = config.substr(config.find('-') + 1);
		protocol params = protocol(argc, argv);
		uint32_t index = from_string<uint32_t>(number.substr(0, number.find_first_not_of("0123456789"))).otherwise(1);

		ledger::wallet wallet = ledger::wallet::from_seed(stringify::text("00000%i", index - 1));
		ledger::validator node;
		node.address = socket_address(params.user.p2p.address, params.user.p2p.port);

		auto mempool = storages::mempoolstate(__func__);
		mempool.apply_validator(node, wallet);

		nds::server_node discovery;
		p2p::server_node consensus;
		nss::server_node& synchronization = *nss::server_node::get();
		rpc::server_node interfaces = rpc::server_node(&consensus);

		service_control control;
		control.bind(discovery.get_entrypoint());
		control.bind(consensus.get_entrypoint());
		control.bind(synchronization.get_entrypoint());
		control.bind(interfaces.get_entrypoint());

		int exit_code = control.launch();
		if (os::process::has_debugger())
		{
			auto* term = console::get();
			term->write("\n");
			term->color_begin(std_color::white, std_color::dark_green);
			term->fwrite("  CONSENSUS TEST FINISHED  ");
			term->color_end();
			term->write("\n\n");
			term->read_char();
		}

		return exit_code;
	}
	/* simplest blockchain explorer for debugging */
	static int explorer(int argc, char* argv[])
	{
		VI_PANIC(argc > 1, "config path argument is required");
		vitex::runtime scope;
		protocol params = protocol(argc, argv);

		auto* term = console::get();
		term->show();

		auto chain = storages::chainstate(__func__);
		auto mempool = storages::mempoolstate(__func__);
		while (true)
		{
			auto command = term->read(1024 * 1024);
			if (command.empty())
				break;

			auto args = stringify::split(command, ' ');
			auto& method = args[0];
			if (method == "account")
			{
				if (args.size() < 3)
					goto not_valid;

				algorithm::pubkeyhash owner = { 0 };
				if (!algorithm::signing::decode_address(args[2], owner))
					goto not_valid;

				auto index = string();
				auto column = string();
				auto row = string();
				auto& state = args[1];
				if (state == "sequence")
				{
					index = states::account_sequence::as_instance_index(owner);
				}
				else if (state == "work")
				{
					column = states::account_work::as_instance_column(owner);
					row = states::account_work::as_instance_row();
				}
				else if (state == "observer")
				{
					if (args.size() < 4)
						goto not_valid;

					column = states::account_observer::as_instance_column(owner);
					row = states::account_observer::as_instance_row(algorithm::asset::id_of_handle(args[3]));
				}
				else if (state == "program")
				{
					index = states::account_program::as_instance_index(owner);
				}
				else if (state == "storage")
				{
					if (args.size() < 4)
						goto not_valid;

					index = states::account_storage::as_instance_index(owner, codec::hex_decode(args[3]));
				}
				else if (state == "reward")
				{
					if (args.size() < 4)
						goto not_valid;

					column = states::account_reward::as_instance_column(owner);
					row = states::account_reward::as_instance_row(algorithm::asset::id_of_handle(args[3]));
				}
				else if (state == "derivation")
				{
					if (args.size() < 4)
						goto not_valid;

					index = states::account_derivation::as_instance_index(owner, algorithm::asset::id_of_handle(args[3]));
				}
				else if (state == "balance")
				{
					if (args.size() < 4)
						goto not_valid;

					column = states::account_balance::as_instance_column(owner);
					row = states::account_balance::as_instance_row(algorithm::asset::id_of_handle(args[3]));
				}
				else if (state == "depository")
				{
					if (args.size() < 4)
						goto not_valid;

					column = states::account_depository::as_instance_column(owner);
					row = states::account_depository::as_instance_row(algorithm::asset::id_of_handle(args[3]));
				}

				auto response = index.empty() ? chain.get_multiform_by_composition(nullptr, column, row, 0) : chain.get_uniform_by_index(nullptr, index, 0);
				if (!response || !*response)
					goto not_found;

				auto data = (*response)->as_schema();
				term->jwrite_line(*data);
				continue;
			}
			else if (method == "witness")
			{
				if (args.size() < 2)
					goto not_valid;

				auto index = string();
				auto column = string();
				auto row = string();
				auto& state = args[1];
				if (state == "program")
				{
					if (args.size() < 3)
						goto not_valid;

					index = states::witness_program::as_instance_index(args[2]);
				}
				else if (state == "event")
				{
					if (args.size() < 3)
						goto not_valid;

					auto hash = uint256_t(args[2], 16);
					index = states::witness_event::as_instance_index(hash);
				}
				else if (state == "address")
				{
					if (args.size() < 5)
						goto not_valid;

					algorithm::pubkeyhash owner = { 0 };
					if (!algorithm::signing::decode_address(args[2], owner))
						goto not_valid;

					column = states::witness_address::as_instance_column(owner);
					row = states::witness_address::as_instance_row(algorithm::asset::id_of_handle(args[3]), args[4], args.size() > 5 ? uint64_t(uint256_t(args[5], 10)) : protocol::now().account.root_address_index);
				}
				else if (state == "transaction")
				{
					if (args.size() < 4)
						goto not_valid;

					index = states::witness_transaction::as_instance_index(algorithm::asset::id_of_handle(args[2]), args[3]);
				}

				auto response = index.empty() ? chain.get_multiform_by_composition(nullptr, column, row, 0) : chain.get_uniform_by_index(nullptr, index, 0);
				if (!response || !*response)
					goto not_found;

				auto data = (*response)->as_schema();
				term->jwrite_line(*data);
				continue;
			}
			else if (method == "tx")
			{
				if (args.size() < 2)
					goto not_valid;

				auto hash = uint256_t(args[1], 16);
				auto context = ledger::transaction_context();
				auto finalized_transaction = context.get_block_transaction_instance(hash);
				if (!finalized_transaction)
				{
					auto stale_transaction = chain.get_transaction_by_hash(hash);
					if (!stale_transaction)
					{
						auto pending_transaction = mempool.get_transaction_by_hash(hash);
						if (!pending_transaction)
							goto not_found;

						auto data = (*pending_transaction)->as_schema();
						term->jwrite_line(*data);
					}
					else
					{
						auto data = (*stale_transaction)->as_schema();
						term->jwrite_line(*data);
					}
				}
				else
				{
					auto data = finalized_transaction->as_schema();
					term->jwrite_line(*data);
				}
				continue;
			}
			else if (method == "tx_message")
			{
				if (args.size() < 2)
					goto not_valid;

				auto hash = uint256_t(args[1], 16);
				auto context = ledger::transaction_context();
				auto finalized_transaction = context.get_block_transaction_instance(hash);
				if (!finalized_transaction)
				{
					auto stale_transaction = chain.get_transaction_by_hash(hash);
					if (!stale_transaction)
					{
						auto pending_transaction = mempool.get_transaction_by_hash(hash);
						if (!pending_transaction)
							goto not_found;

						auto data = format::util::encode_0xhex((*pending_transaction)->as_message().data);
						term->write_line(data);
					}
					else
					{
						auto data = format::util::encode_0xhex((*stale_transaction)->as_message().data);
						term->write_line(data);
					}
				}
				else
				{
					auto data = format::util::encode_0xhex(finalized_transaction->as_message().data);
					term->write_line(data);
				}
				continue;
			}
			else if (method == "txns")
			{
				if (args.size() < 2)
					goto not_valid;

				algorithm::pubkeyhash owner = { 0 };
				if (!algorithm::signing::decode_address(args[1], owner))
					goto not_valid;

				auto page = (uint64_t)uint256_t(args.size() > 2 ? args[2] : "0", 10);
				auto response = chain.get_block_transactions_by_owner(std::numeric_limits<int64_t>::max(), owner, 1, 512 * page, 512);
				if (!response)
					goto not_found;

				auto data = uptr<schema>(var::set::array());
				for (auto& item : *response)
					data->push(item.as_schema().reset());
				term->jwrite_line(*data);
				continue;
			}
			else if (method == "txns_hashes")
			{
				if (args.size() < 2)
					goto not_valid;

				algorithm::pubkeyhash owner = { 0 };
				if (!algorithm::signing::decode_address(args[1], owner))
					goto not_valid;

				auto page = (uint64_t)uint256_t(args.size() > 2 ? args[2] : "0", 10);
				auto response = chain.get_transactions_by_owner(std::numeric_limits<int64_t>::max(), owner, 1, 512 * page, 512);
				if (!response)
					goto not_found;

				auto data = uptr<schema>(var::set::array());
				for (auto& item : *response)
					data->push(var::set::string(algorithm::encoding::encode_0xhex256(item->as_hash())));
				term->jwrite_line(*data);
				continue;
			}
			else if (method == "block")
			{
				if (args.size() < 2)
					goto not_valid;

				auto number = uint64_t(uint256_t(args[1], 10));
				auto hash = uint256_t(args[1], 16);
				auto response = chain.get_block_by_hash(hash);
				if (!response)
				{
					response = chain.get_block_by_number(number);
					if (!response)
						goto not_found;
				}

				auto data = response->as_schema();
				term->jwrite_line(*data);
				continue;
			}
			else if (method == "block_message")
			{
				if (args.size() < 2)
					goto not_valid;

				auto number = uint64_t(uint256_t(args[1], 10));
				auto hash = uint256_t(args[1], 16);
				auto response = chain.get_block_by_hash(hash);
				if (!response)
				{
					response = chain.get_block_by_number(number);
					if (!response)
						goto not_found;
				}

				auto data = format::util::encode_0xhex(response->as_message().data);
				term->write_line(data);
				continue;
			}
			else if (method == "block_body")
			{
				if (args.size() < 2)
					goto not_valid;

				auto number = uint64_t(uint256_t(args[1], 10));
				auto hash = uint256_t(args[1], 16);
				auto response1 = chain.get_block_header_by_hash(hash);
				if (!response1)
				{
					response1 = chain.get_block_header_by_number(number);
					if (!response1)
						goto not_found;
				}

				auto data = response1->as_schema();
				auto response2 = chain.get_block_transaction_hashset(response1->number);
				if (response2)
				{
					auto* hashes = data->set("transactions", var::set::array());
					for (auto& item : *response2)
						hashes->push(var::string(algorithm::encoding::encode_0xhex256(item)));
				}
				auto response3 = chain.get_block_statetrie_hashset(response1->number);
				if (response3)
				{
					auto* hashes = data->set("states", var::set::array());
					for (auto& item : *response3)
						hashes->push(var::string(algorithm::encoding::encode_0xhex256(item)));
				}
				term->jwrite_line(*data);
				continue;
			}
			else if (method == "block_header")
			{
				if (args.size() < 2)
					goto not_valid;

				auto number = uint64_t(uint256_t(args[1], 10));
				auto hash = uint256_t(args[1], 16);
				auto response1 = chain.get_block_header_by_hash(hash);
				if (!response1)
				{
					response1 = chain.get_block_header_by_number(number);
					if (!response1)
						goto not_found;
				}

				auto data = response1->as_schema();
				term->jwrite_line(*data);
				continue;
			}
			else if (method == "blocks")
			{
				if (args.size() < 3)
					goto not_valid;

				uptr<schema> data = var::set::array();
				bool validate = args.size() > 3 ? (uint256_t(args[3], 10) > 0) : false, written = false;
				uint64_t block_number = uint64_t(uint256_t(args[1], 10));
				uint64_t block_count = uint64_t(uint256_t(args[2], 10));
				uint64_t current_number = block_number;
				auto chain = storages::chainstate(__func__);
				if (current_number < chain.get_checkpoint_block_number().otherwise(0))
				{
					term->write_line("block cannot be validated without re-executing entire blockchain");
					continue;
				}

				auto parent_block = chain.get_block_header_by_number(block_number > 1 ? block_number - 1 : 0);
				while (current_number < block_number + block_count)
				{
					auto next = chain.get_block_by_number(current_number++);
					if (!next)
						break;

					auto target = *data;
					auto proof = next->as_proof(parent_block.address());
					auto block_info = next->as_schema();
					size_t tx_index = 0;
					for (auto& item : block_info->get("transactions")->get_childs())
					{
						auto& tx = next->transactions[tx_index++];
						auto* tx_info = item->get("transaction");
						auto* claim_info = item->get("receipt");
						tx_info->set("merkle_test", var::string(proof.has_transaction(tx.receipt.transaction_hash) ? "passed" : "failed"));
						claim_info->set("merkle_test", var::string(proof.has_receipt(tx.receipt.as_hash()) ? "passed" : "failed"));
					}

					size_t state_index = 0;
					for (auto& item : block_info->get("states")->get_childs())
						item->set("merkle_test", var::string(proof.has_state(algorithm::encoding::decode_0xhex256(item->get_var("hash").get_blob())) ? "passed" : "failed"));

					auto validity = next->verify_validity(parent_block.address());
					auto integrity = next->verify_integrity(parent_block.address());
					auto validation = validate ? next->validate(parent_block.address()) : expects_lr<void>(expectation::met);
					block_info->set("validity_test", var::string(validity ? "passed" : validity.error().what()));
					block_info->set("integrity_test", var::string(integrity ? "passed" : integrity.error().what()));
					block_info->set("validation_test", var::string(validate ? (validation ? "passed" : validation.error().what()) : "unchecked"));
					block_info->set("merkle_test", proof.as_schema().reset());
					target->push(block_info.reset());
					parent_block = *next;

					if (data->size() > 32)
					{
						term->jwrite_line(*data);
						data->clear();
					}
				}
				if (!written || !data->empty())
				{
					uptr<stream> stream = *os::file::open(*os::directory::get_module() + "/test.json", file_mode::binary_write_only); string offset;
					schema::convert_to_json(*data, [&term, &stream, &offset](var_form pretty, const std::string_view& buffer)
					{
						if (!buffer.empty())
						{
							stream->write((uint8_t*)buffer.data(), buffer.size());
							term->write(buffer);
						}

						switch (pretty)
						{
							case vitex::core::var_form::tab_decrease:
								offset.erase(offset.size() - 2);
								break;
							case vitex::core::var_form::tab_increase:
								offset.append(2, ' ');
								break;
							case vitex::core::var_form::write_space:
								stream->write((uint8_t*)" ", 1);
								term->write(" ");
								break;
							case vitex::core::var_form::write_line:
								stream->write((uint8_t*)"\n", 1);
								term->write("\n");
								break;
							case vitex::core::var_form::write_tab:
								stream->write((uint8_t*)offset.data(), offset.size());
								term->write(offset);
								break;
							default:
								break;
						}
					});
					term->write_char('\n');
				}
				continue;
			}
			else if (method == "blocks_hashes")
			{
				if (args.size() < 3)
					goto not_valid;

				uint64_t block_number = uint64_t(uint256_t(args[1], 10));
				uint64_t block_count = uint64_t(uint256_t(args[2], 10));
				auto chain = storages::chainstate(__func__);
				auto response = chain.get_block_hashset(block_number, block_count);
				if (!response)
					goto not_found;

				auto data = uptr<schema>(var::set::array());
				for (auto& item : *response)
					data->push(var::set::string(algorithm::encoding::encode_0xhex256(item)));
				term->jwrite_line(*data);
				continue;
			}
			else if (method == "parse")
			{
				if (args.size() < 2)
					goto not_valid;

				format::variables data;
				format::stream message = format::stream(args[1]);
				format::variables_util::deserialize_flat_from(message, &data);
				term->write_line(format::variables_util::as_constant_json(data));
				continue;
			}
		not_valid:
			term->write_line("command is not valid");
			continue;
		not_found:
			term->write_line("value not found");
			continue;
		}

		if (os::process::has_debugger())
		{
			auto* term = console::get();
			term->write("\n");
			term->color_begin(std_color::white, std_color::dark_green);
			term->fwrite("  EXPLORER TEST FINISHED  ");
			term->color_end();
			term->write("\n\n");
			term->read_char();
		}

		return 0;
	}
	/* mediator node for debugging */
	static int mediator(int argc, char* argv[])
	{
		VI_PANIC(argc > 1, "config path argument is required");
		vitex::runtime scope;
		protocol params = protocol(argc, argv);

		auto* term = console::get();
		term->show();

		static bool is_active = true;
		os::process::bind_signal(signal_code::SIG_INT, [](int) { is_active = false; });

		schedule::desc policy;
		schedule* queue = schedule::get();
		queue->start(policy);

		auto* server = nss::server_node::get();
		auto asset = algorithm::asset::id_of("XMR");
		auto parent = server->new_master_wallet(asset, string("123456"));
		auto child = mediator::dynamic_wallet(*server->new_signing_wallet(asset, *parent, 0));
		for (auto& address : child.signing_child->addresses)
			server->enable_wallet_address(asset, *child.get_binding(), address.second, *child.signing_child->address_index);

		coasync<void>([&]() -> promise<void>
		{
			auto balance = coawait(server->calculate_balance(asset, child));
			auto info = parent->as_schema();
			auto* wallet_info = info->set("wallet", child.signing_child->as_schema().reset());
			wallet_info->set("balance", var::string(balance ? balance->to_string().c_str() : "?"));
			term->jwrite_line(*info);

			server->startup();
			for (size_t i = 0; i < 0; i++)
			{
				uint256_t hash;
				algorithm::encoding::encode_uint256((uint8_t*)crypto::random_bytes(32)->data(), hash);
				auto transaction = coawait(server->submit_transaction(hash, asset, mediator::dynamic_wallet(child), { mediator::transferer("bcrt1p5dy9ef2lngvmlx6edjgp88hemj03uszt3zlqrc252vlxp3jf27vq648qmh", optional::none, 0.01) }, mediator::base_fee(0.000003, 1)));
				if (!transaction)
					break;
			}

			while (is_active)
			{
				promise<void> future;
				queue->set_timeout(200, [future]() mutable { future.set(); });
				coawait(std::move(future));
			}

			server->shutdown();
			coreturn_void;
		}).wait();

		while (queue->dispatch());
		queue->stop();

		if (os::process::has_debugger())
		{
			auto* term = console::get();
			term->write("\n");
			term->color_begin(std_color::white, std_color::dark_green);
			term->fwrite("  MEDIATOR TEST FINISHED  ");
			term->color_end();
			term->write("\n\n");
			term->read_char();
		}

		return 0;
	}
	/* blockchain derived from partial coverage test with 1920 additional blocks filled with configurable entropy transactions (non-zero balance accounts, valid regtest chain, entropy 0 - low entropy, entropy 1 - medium entropy, entropy 2 - high entropy) */
	static int benchmark(int argc, char* argv[], uint8_t entropy)
	{
		VI_PANIC(argc > 1, "config path argument is required");
		vitex::runtime scope;
		protocol params = protocol(argc, argv);

		auto* term = console::get();
		term->show();

		auto* queue = schedule::get();
		queue->start(schedule::desc());

		const size_t block_count = 1920;
		const size_t transaction_count = (size_t)(uint64_t)(ledger::block::get_gas_limit() / transactions::transfer().get_gas_estimate());
		const decimal starting_account_balance = decimal(500).truncate(12);
		auto checkpoint = [&](vector<uptr<ledger::transaction>>&& transactions, vector<tests::account>& users)
		{
			static uint64_t cumulative_transaction_count = 0, cumulative_state_count = 0;
			auto cumulative_query_count = (uint64_t)ledger::storage_util::get_thread_queries(); term->capture_time();
			auto block = tests::new_block_from_list(nullptr, users, std::move(transactions));
			auto time = term->get_captured_time();
			cumulative_transaction_count += block.transaction_count;
			cumulative_state_count += block.state_count;
			term->fwrite_line("%05" PRIu64 ": %s = (d: %s / %.2f ms, t: %" PRIu64 " / %.2f hz, s: %" PRIu64 " / %.2f hz, q: %" PRIu64 " / %.2f hz)",
				block.number, algorithm::encoding::encode_0xhex256(block.as_hash()).c_str(),
				block.target.difficulty().to_string().c_str(), time,
				cumulative_transaction_count, 1000.0 * (double)block.transaction_count / time,
				cumulative_state_count, 1000.0 * (double)block.state_count / time,
				cumulative_query_count, 1000.0 * (double)((uint64_t)ledger::storage_util::get_thread_queries() - cumulative_query_count) / time);
		};

		vector<tests::account> proposers;
		tests::blockchain_partial_coverage(&proposers);

		auto& [user1, user1_sequence] = proposers[0];
		auto& [user2, user2_sequence] = proposers[1];
		auto chain = storages::chainstate(__func__);
		auto context = ledger::transaction_context();
		auto user1_addresses = *context.get_witness_addresses_by_purpose(user1.public_key_hash, states::address_type::custodian, 0, 128);
		auto user1_custodian_address = std::find_if(user1_addresses.begin(), user1_addresses.end(), [](states::witness_address& item) { return item.asset == algorithm::asset::id_of("BTC"); });
		VI_PANIC(user1_custodian_address != user1_addresses.end(), "user 1 custodian address not found");

		if (entropy == 0)
		{
			const decimal outgoing_account_balance = starting_account_balance / decimal(block_count * (transaction_count + 64));
			const decimal incoming_quantity = starting_account_balance;
			auto* incoming_claim = memory::init<transactions::incoming_claim>();
			incoming_claim->set_asset("BTC");
			incoming_claim->set_estimate_gas(decimal::zero());
			incoming_claim->set_witness(883669,
				"222fc360affb804ad2c34bba2269b36a64a86f017d05a9a60b237e8587bfc52b", 0.0,
				{ mediator::transferer("mmtubFoJvXrBuBUQFf1RrowXUbsiPDYnYS", optional::none, decimal(incoming_quantity)) },
				{ mediator::transferer(user1_custodian_address->addresses.begin()->second, user1_custodian_address->address_index, decimal(incoming_quantity)) });
			VI_PANIC(incoming_claim->sign(user2.secret_key, user2_sequence++), "claim not signed");

			auto genesis = vector<uptr<ledger::transaction>>();
			genesis.push_back(incoming_claim);
			checkpoint(std::move(genesis), proposers);

			auto receiver = ledger::wallet::from_seed("000002");
			for (size_t i = 0; i < block_count; i++)
			{
				vector<uptr<ledger::transaction>> transactions;
				transactions.resize(transaction_count);
				parallel::wail_all(parallel::for_each(transactions.begin(), transactions.end(), ELEMENTS_FEW, [&](uptr<ledger::transaction>& item)
				{
					double balance = (double)(std::max<uint64_t>(1000, crypto::random() % 10000)) / 10000.0;

					auto* transaction = memory::init<transactions::transfer>();
					transaction->set_asset("BTC");
					transaction->set_estimate_gas(decimal::zero());
					transaction->set_to(receiver.public_key_hash, decimal(outgoing_account_balance).truncate(12) * decimal(balance));
					VI_PANIC(transaction->sign(user1.secret_key, user1_sequence++), "transfer not signed");
					item = transaction;
				}));
				std::sort(transactions.begin(), transactions.end(), [](const uptr<ledger::transaction>& a, const uptr<ledger::transaction>& b) { return a->sequence < b->sequence; });
				checkpoint(std::move(transactions), proposers);
			}
		}
		else if (entropy == 1)
		{
			const size_t sender_count = 16;
			const size_t receiver_count = 32;
			const decimal outgoing_account_balance = starting_account_balance / decimal(block_count * (transaction_count + 64) * sender_count);
			const decimal incoming_quantity = starting_account_balance * sender_count;
			auto* incoming_claim = memory::init<transactions::incoming_claim>();
			incoming_claim->set_asset("BTC");
			incoming_claim->set_estimate_gas(decimal::zero());
			incoming_claim->set_witness(883669,
				"222fc360affb804ad2c34bba2269b36a64a86f017d05a9a60b237e8587bfc52b", 0.0,
				{ mediator::transferer("mmtubFoJvXrBuBUQFf1RrowXUbsiPDYnYS", optional::none, decimal(incoming_quantity)) },
				{ mediator::transferer(user1_custodian_address->addresses.begin()->second, user1_custodian_address->address_index, decimal(incoming_quantity)) });
			VI_PANIC(incoming_claim->sign(user2.secret_key, user2_sequence++), "claim not signed");

			auto genesis = vector<uptr<ledger::transaction>>();
			genesis.push_back(incoming_claim);
			checkpoint(std::move(genesis), proposers);

			vector<tests::account> senders;
			senders.reserve(sender_count);
			for (size_t i = 0; i < sender_count; i++)
				senders.emplace_back(tests::account(ledger::wallet::from_seed(stringify::text("00001%i", (int)i)), 1));

			vector<tests::account> receivers;
			receivers.reserve(receiver_count);
			for (size_t i = 0; i < receiver_count; i++)
				receivers.emplace_back(tests::account(ledger::wallet::from_seed(stringify::text("00002%i", (int)i)), 1));

			auto* omnitransfer = memory::init<transactions::omnitransfer>();
			omnitransfer->set_asset("BTC");
			for (auto& sender : senders)
				omnitransfer->set_to(sender.wallet.public_key_hash, starting_account_balance);
			omnitransfer->set_gas(decimal::zero(), ledger::block::get_gas_limit());
			VI_PANIC(omnitransfer->sign(user1.secret_key, user1_sequence++), "omnitransfer not signed");

			genesis = vector<uptr<ledger::transaction>>();
			genesis.push_back(omnitransfer);
			checkpoint(std::move(genesis), proposers);

			for (size_t i = 0; i < block_count; i++)
			{
				vector<uptr<ledger::transaction>> transactions;
				transactions.resize(transaction_count);
				parallel::wail_all(parallel::for_each(transactions.begin(), transactions.end(), ELEMENTS_FEW, [&](uptr<ledger::transaction>& item)
				{
					double balance = (double)(std::max<uint64_t>(1000, crypto::random() % 10000)) / 10000.0;
					auto& sender = senders[crypto::random() % senders.size()];
					auto& receiver = receivers[crypto::random() % receivers.size()];

					auto* transaction = memory::init<transactions::transfer>();
					transaction->set_asset("BTC");
					transaction->set_estimate_gas(decimal::zero());
					transaction->set_to(receiver.wallet.public_key_hash, decimal(outgoing_account_balance).truncate(12) * decimal(balance));
					VI_PANIC(transaction->sign(sender.wallet.secret_key, sender.sequence++), "transfer not signed");
					item = transaction;
				}));
				std::sort(transactions.begin(), transactions.end(), [](const uptr<ledger::transaction>& a, const uptr<ledger::transaction>& b) { return a->sequence < b->sequence; });
				checkpoint(std::move(transactions), proposers);
			}
		}
		else
		{
			const size_t sender_count = transaction_count;
			const decimal outgoing_account_balance = starting_account_balance / decimal(block_count * (transaction_count + 64) * sender_count);
			const decimal incoming_quantity = starting_account_balance * sender_count * 2;
			auto* incoming_claim = memory::init<transactions::incoming_claim>();
			incoming_claim->set_asset("BTC");
			incoming_claim->set_estimate_gas(decimal::zero());
			incoming_claim->set_witness(883669,
				"222fc360affb804ad2c34bba2269b36a64a86f017d05a9a60b237e8587bfc52b", 0.0,
				{ mediator::transferer("mmtubFoJvXrBuBUQFf1RrowXUbsiPDYnYS", optional::none, decimal(incoming_quantity)) },
				{ mediator::transferer(user1_custodian_address->addresses.begin()->second, user1_custodian_address->address_index, decimal(incoming_quantity)) });
			VI_PANIC(incoming_claim->sign(user2.secret_key, user2_sequence++), "claim not signed");

			auto genesis = vector<uptr<ledger::transaction>>();
			genesis.push_back(incoming_claim);
			checkpoint(std::move(genesis), proposers);

			vector<tests::account> senders;
			senders.reserve(sender_count);
			for (size_t i = 0; i < sender_count; i++)
				senders.emplace_back(tests::account({ ledger::wallet::from_seed(stringify::text("00001%i", (int)i)), 1 }));

			auto* omnitransfer = memory::init<transactions::omnitransfer>();
			omnitransfer->set_asset("BTC");
			for (auto& sender : senders)
				omnitransfer->set_to(sender.wallet.public_key_hash, starting_account_balance);
			omnitransfer->set_gas(decimal::zero(), ledger::block::get_gas_limit());
			VI_PANIC(omnitransfer->sign(user1.secret_key, user1_sequence++), "omnitransfer not signed");

			genesis = vector<uptr<ledger::transaction>>();
			genesis.push_back(omnitransfer);
			checkpoint(std::move(genesis), proposers);

			for (size_t i = 0; i < block_count; i++)
			{
				vector<uptr<ledger::transaction>> transactions;
				transactions.resize(transaction_count);
				parallel::wail_all(parallel::for_each(transactions.begin(), transactions.end(), ELEMENTS_FEW, [&](uptr<ledger::transaction>& item)
				{
					double balance = (double)(std::max<uint64_t>(1000, crypto::random() % 10000)) / 10000.0;
					auto& sender = senders[crypto::random() % senders.size()];

					uint8_t receiver[20];
					crypto::fill_random_bytes(receiver, sizeof(receiver));

					auto* transaction = memory::init<transactions::transfer>();
					transaction->set_asset("BTC");
					transaction->set_estimate_gas(decimal::zero());
					transaction->set_to(receiver, decimal(outgoing_account_balance).truncate(12) * decimal(balance));
					VI_PANIC(transaction->sign(sender.wallet.secret_key, sender.sequence++), "transfer not signed");
					item = transaction;
				}));
				std::sort(transactions.begin(), transactions.end(), [](const uptr<ledger::transaction>& a, const uptr<ledger::transaction>& b) { return a->sequence < b->sequence; });
				checkpoint(std::move(transactions), proposers);
			}
		}

		queue->stop();
		if (os::process::has_debugger())
		{
			auto* term = console::get();
			term->write("\n");
			term->color_begin(std_color::white, std_color::dark_green);
			term->fwrite("  BENCHMARK TEST FINISHED  ");
			term->color_end();
			term->write("\n\n");
			term->read_char();
		}

		return 0;
	}
	/* test case runner for regressuib testing */
	static int regression(int argc, char* argv[])
	{
		VI_PANIC(argc > 1, "config path argument is required");
		vitex::runtime scope;
		protocol params = protocol(argc, argv);

		auto* term = console::get();
		term->show();

		size_t executions = 0;
		vector<std::pair<std::string_view, std::function<void()>>> cases =
		{
			{ "generic / integer serialization", &tests::generic_integer_serialization },
			{ "generic / integer conversion", &tests::generic_integer_conversion },
			{ "generic / message serialization", &tests::generic_message_serialization },
			{ "cryptography / nakamoto pow 240bits", &tests::cryptography_nakamoto },
			{ "cryptography / wesolowski pow 90x", &tests::cryptography_wesolowski },
			{ "cryptography / signatures", &tests::cryptography_signatures },
			{ "cryptography / wallet", &tests::cryptography_wallet },
			{ "cryptography / wallet sharing", &tests::cryptography_wallet_sharing },
			{ "cryptography / wallet messaging", &tests::cryptography_wallet_messaging },
			{ "cryptography / transaction", &tests::cryptography_transaction },
			{ "cryptography / merkle tree", &tests::cryptography_merkle_tree },
			{ "cryptography / multichain", &tests::cryptography_multichain },
			{ "blockchain / full coverage", std::bind(&tests::blockchain_full_coverage, (vector<tests::account>*)nullptr) },
			{ "blockchain / verification", &tests::blockchain_verification },
			{ "blockchain / partial coverage", std::bind(&tests::blockchain_partial_coverage, (vector<tests::account>*)nullptr) },
			{ "blockchain / verification", &tests::blockchain_verification },
			{ "blockchain / gas estimation", &tests::blockchain_gas_estimation },
		};
		for (size_t i = 0; i < cases.size(); i++)
		{
			auto& condition = cases[i];
			term->color_begin(std_color::black, std_color::yellow);
			term->fwrite("  ===>  %s  <===  ", condition.first.data());
			term->color_end();
			term->write_char('\n');
			term->capture_time();

			condition.second();

			double time = term->get_captured_time();
			term->color_begin(std_color::white, std_color::dark_green);
			term->fwrite("  TEST PASS %.1fms %.2f%%  ", time, 100.0 * (double)(i + 1) / (double)cases.size());
			term->color_end();
			term->write("\n\n");
		}

		if (os::process::has_debugger())
		{
			auto* term = console::get();
			term->color_begin(std_color::white, std_color::dark_green);
			term->fwrite("  REGRESSION TEST FINISHED  ");
			term->color_end();
			term->write("\n\n");
			term->read_char();
		}

		return 0;
	}
};

int main(int argc, char* argv[])
{
	return apps::regression(argc, argv);
}