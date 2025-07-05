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
		std::atomic<uint64_t> nonce;

		account() = default;
		account(const ledger::wallet& new_wallet, uint64_t new_nonce) : wallet(new_wallet), nonce(new_nonce)
		{
		}
		account(account&&) = default;
		account(const account& other) : wallet(other.wallet), nonce(other.nonce.load())
		{
		}
		account& operator= (account&&) = default;
		account& operator= (const account& other)
		{
			if (&other == this)
				return *this;

			wallet = other.wallet;
			nonce = other.nonce.load();
			return *this;
		}
	};

	struct participant
	{
		algorithm::composition::keypair keypair;
		uint256_t seed = 0;
	};

	class generators
	{
	public:
		static void account_transfer_stage_1(vector<uptr<ledger::transaction>>& transactions, vector<account>& users)
		{
			auto& [user1, user1_nonce] = users[0];
			auto& [user2, user2_nonce] = users[1];
			auto* transfer_ethereum = memory::init<transactions::transfer>();
			transfer_ethereum->set_asset("ETH");
			transfer_ethereum->set_to(algorithm::encoding::to_subaddress(user2.public_key_hash), 0.1);
			transfer_ethereum->set_to(algorithm::encoding::to_subaddress(user2.public_key_hash), 0.2);
			transfer_ethereum->set_to(algorithm::encoding::to_subaddress(user2.public_key_hash), 0.3);
			transfer_ethereum->set_to(algorithm::encoding::to_subaddress(user2.public_key_hash), 0.4);
			transfer_ethereum->set_to(algorithm::encoding::to_subaddress(user2.public_key_hash), 0.5);
			VI_PANIC(transfer_ethereum->sign(user1.secret_key, user1_nonce++, decimal::zero()), "transfer not signed");
			transactions.push_back(transfer_ethereum);

			auto user_test = ledger::wallet::from_seed(std::string_view((char*)user1.secret_key, sizeof(user1.secret_key)));
			auto* transfer_ripple = memory::init<transactions::transfer>();
			transfer_ripple->set_asset("XRP");
			transfer_ripple->set_to(algorithm::encoding::to_subaddress(user2.public_key_hash), 9.0);
			transfer_ripple->set_to(algorithm::encoding::to_subaddress(user2.public_key_hash, user1.public_key_hash), 1.0);
			transfer_ripple->set_to(algorithm::encoding::to_subaddress(user_test.public_key_hash), 5.0);
			VI_PANIC(transfer_ripple->sign(user1.secret_key, user1_nonce++, decimal::zero()), "transfer not signed");
			transactions.push_back(transfer_ripple);

			auto* transfer_bitcoin = memory::init<transactions::transfer>();
			transfer_bitcoin->set_asset("BTC");
			transfer_bitcoin->set_to(algorithm::encoding::to_subaddress(user2.public_key_hash), 0.1);
			VI_PANIC(transfer_bitcoin->sign(user1.secret_key, user1_nonce++, decimal::zero()), "transfer not signed");
			transactions.push_back(transfer_bitcoin);
		}
		static void account_transfer_stage_2(vector<uptr<ledger::transaction>>& transactions, vector<account>& users)
		{
			auto& [user1, user1_nonce] = users[0];
			auto& [user2, user2_nonce] = users[1];
			auto* transfer_ethereum = memory::init<transactions::transfer>();
			transfer_ethereum->set_asset("ETH");
			transfer_ethereum->set_to(algorithm::encoding::to_subaddress(user1.public_key_hash), 0.01);
			transfer_ethereum->set_to(algorithm::encoding::to_subaddress(user1.public_key_hash), 0.02);
			transfer_ethereum->set_to(algorithm::encoding::to_subaddress(user1.public_key_hash), 0.03);
			transfer_ethereum->set_to(algorithm::encoding::to_subaddress(user1.public_key_hash), 0.04);
			transfer_ethereum->set_to(algorithm::encoding::to_subaddress(user1.public_key_hash), 0.05);
			VI_PANIC(transfer_ethereum->sign(user2.secret_key, user2_nonce++, std::string_view("0.00000001")), "transfer not signed");
			transactions.push_back(transfer_ethereum);

			auto user_test = ledger::wallet::from_seed(std::string_view((char*)user1.secret_key, sizeof(user1.secret_key)));
			auto* transfer_ripple = memory::init<transactions::transfer>();
			transfer_ripple->set_asset("XRP");
			transfer_ripple->set_to(algorithm::encoding::to_subaddress(user1.public_key_hash), 5.0);
			VI_PANIC(transfer_ripple->sign(user_test.secret_key, 1, decimal::zero()), "transfer not signed");
			transactions.push_back(transfer_ripple);
		}
		static void account_transfer_to_account(vector<uptr<ledger::transaction>>& transactions, vector<account>& users, size_t user_id, const algorithm::asset_id& asset, const std::string_view& address, const decimal& value)
		{
			auto& [user1, user1_nonce] = users[user_id];
			algorithm::subpubkeyhash sub_public_key_hash;
			algorithm::signing::decode_subaddress(address, sub_public_key_hash);

			auto* transfer_asset = memory::init<transactions::transfer>();
			transfer_asset->asset = asset;
			transfer_asset->set_to(sub_public_key_hash, value);
			VI_PANIC(transfer_asset->sign(user1.secret_key, user1_nonce++, decimal::zero()), "transfer not signed");
			transactions.push_back(transfer_asset);
		}
		static void account_transaction_rollup(vector<uptr<ledger::transaction>>& transactions, vector<account>& users)
		{
			auto& [user1, user1_nonce] = users[0];
			auto& [user2, user2_nonce] = users[1];
			auto* multi_asset_rollup = memory::init<transactions::rollup>();
			multi_asset_rollup->set_asset("ETH");

			auto transfer_ethereum1 = transactions::transfer();
			transfer_ethereum1.set_to(algorithm::encoding::to_subaddress(user2.public_key_hash), 0.1);
			VI_PANIC(multi_asset_rollup->import_internal_transaction(transfer_ethereum1, user1.secret_key), "transfer not signed");

			auto transfer_ethereum2 = transactions::transfer();
			transfer_ethereum2.set_to(algorithm::encoding::to_subaddress(user2.public_key_hash), 0.2);
			VI_PANIC(multi_asset_rollup->import_internal_transaction(transfer_ethereum2, user1.secret_key), "transfer not signed");

			auto transfer_ethereum3 = transactions::transfer();
			transfer_ethereum3.set_to(algorithm::encoding::to_subaddress(user1.public_key_hash), 0.2);
			VI_PANIC(multi_asset_rollup->import_external_transaction(transfer_ethereum3, user2.secret_key, user2_nonce++), "transfer not signed");

			auto transfer_ripple1 = transactions::transfer();
			transfer_ripple1.set_asset("XRP");
			transfer_ripple1.set_to(algorithm::encoding::to_subaddress(user2.public_key_hash), 1);
			VI_PANIC(multi_asset_rollup->import_internal_transaction(transfer_ripple1, user1.secret_key), "transfer not signed");

			auto transfer_ripple2 = transactions::transfer();
			transfer_ripple2.set_asset("XRP");
			transfer_ripple2.set_to(algorithm::encoding::to_subaddress(user2.public_key_hash), 2);
			VI_PANIC(multi_asset_rollup->import_internal_transaction(transfer_ripple2, user1.secret_key), "transfer not signed");

			auto transfer_ripple3 = transactions::transfer();
			transfer_ripple3.set_asset("XRP");
			transfer_ripple3.set_to(algorithm::encoding::to_subaddress(user1.public_key_hash), 2);
			VI_PANIC(multi_asset_rollup->import_external_transaction(transfer_ripple3, user2.secret_key, user2_nonce++), "transfer not signed");

			auto transfer_bitcoin1 = transactions::transfer();
			transfer_bitcoin1.set_asset("BTC");
			transfer_bitcoin1.set_to(algorithm::encoding::to_subaddress(user2.public_key_hash), 0.001);
			VI_PANIC(multi_asset_rollup->import_internal_transaction(transfer_bitcoin1, user1.secret_key), "transfer not signed");

			auto transfer_bitcoin2 = transactions::transfer();
			transfer_bitcoin2.set_asset("BTC");
			transfer_bitcoin2.set_to(algorithm::encoding::to_subaddress(user2.public_key_hash), 0.002);
			VI_PANIC(multi_asset_rollup->import_internal_transaction(transfer_bitcoin2, user1.secret_key), "transfer not signed");

			auto transfer_bitcoin3 = transactions::transfer();
			transfer_bitcoin3.set_asset("BTC");
			transfer_bitcoin3.set_to(algorithm::encoding::to_subaddress(user1.public_key_hash), 0.002);
			VI_PANIC(multi_asset_rollup->import_external_transaction(transfer_bitcoin3, user2.secret_key, user2_nonce++), "transfer not signed");

			VI_PANIC(multi_asset_rollup->sign(user1.secret_key, user1_nonce++, decimal::zero()), "rollup not signed");
			transactions.push_back(multi_asset_rollup);
		}
		static void account_program_deployment(vector<uptr<ledger::transaction>>& transactions, vector<account>& users)
		{
			auto& [user1, user1_nonce] = users[0];
			ledger::wallet token_contract = ledger::wallet::from_seed(string("token") + string((char*)user1.secret_key, sizeof(user1.secret_key)));
			std::string_view token_program = VI_STRINGIFY((
			class token_storage
			{
				address account;
				string name;
				string symbol;
				uint8 decimals = 0;
				uint256 supply = 0;
			}

			class token_transfer
			{
				address from;
				address to;
				uint256 value = 0;
			}

			token_storage construct(instrset::rwptr@, const uint256&in value)
			{
				token_storage token;
				token.account = tx::from();
				token.name = "Test Token";
				token.symbol = "TT";
				token.decimals = 2;
				token.supply = value;

				kvm::set(uint8(0), token);
				kvm::set_if(token.account, value, value > 0);
				return token;
			}
			token_transfer transfer(instrset::rwptr@, const address&in to, const uint256&in value)
			{
				address from = tx::from();
				uint256 input = balance_of(null, from);
				uint256 output = balance_of(null, to);
				uint256 from_delta = input - value, to_delta = output + value;
				require(from_delta <= input, from.to_string() + ": illegal operation - insufficient balance");
				require(to_delta >= output, to.to_string() + ": illegal operation - balance overflow");
				kvm::set_if(from, from_delta, from_delta > 0);
				kvm::set_if(to, to_delta, to_delta > 0);

				token_transfer event;
				event.from = from;
				event.to = to;
				event.value = value;
				return event;
			}
			uint256 mint(instrset::rwptr@, const uint256&in value)
			{
				token_storage token = info(null);
				require(token.account == tx::from(), "illegal operation - operation not permitted");

				uint256 output = balance_of(null, token.account);
				uint256 supply_delta = token.supply + value;
				uint256 to_delta = output + value;
				require(supply_delta >= token.supply, tx::to().to_string() + ": illegal operation - token supply overflow");
				require(to_delta >= output, token.account.to_string() + ": illegal operation - balance overflow");

				token.supply = supply_delta;
				kvm::set(uint8(0), token);
				kvm::set_if(token.account, to_delta, to_delta > 0);
				return to_delta;
			}
			uint256 burn(instrset::rwptr@, const uint256&in value)
			{
				token_storage token = info(null);
				require(token.account == tx::from(), "illegal operation - operation not permitted");

				uint256 output = balance_of(null, token.account);
				uint256 supply_delta = token.supply - value;
				uint256 to_delta = output - value;
				require(supply_delta <= token.supply, "token supply will underflow (" + token.supply.to_string() + " < " + value.to_string() + ")");
				require(to_delta <= output, "account balance will underflow (" + output.to_string() + " < " + value.to_string() + ")");

				token.supply = supply_delta;
				kvm::set(uint8(0), token);
				kvm::set_if(token.account, to_delta, to_delta > 0);
				return to_delta;
			}
			uint256 balance_of(instrset::rptr@, const address&in account)
			{
				uint256 output = 0;
				kvm::load(account, output);
				return output;
			}
			token_storage info(instrset::rptr@)
			{
				return kvm::get<token_storage>(uint8(0));
			}));

			auto* deployment_ethereum1 = memory::init<transactions::deployment>();
			deployment_ethereum1->set_asset("ETH");
			deployment_ethereum1->set_program_calldata(decimal::zero(), token_program.substr(1, token_program.size() - 2), { format::variable(1000000u) });
			deployment_ethereum1->sign_program(token_contract.secret_key);
			VI_PANIC(deployment_ethereum1->sign(user1.secret_key, user1_nonce++, decimal::zero()), "deployment not signed");
			transactions.push_back(deployment_ethereum1);

			ledger::wallet bridge_contract = ledger::wallet::from_seed(string("bridge") + string((char*)user1.secret_key, sizeof(user1.secret_key)));
			std::string_view bridge_program = VI_STRINGIFY((
			void construct(instrset::rwptr@, const address&in token_account)
			{
				kvm::set(uint8(0), token_account);
			}
			uint256 balance_of_test_token(instrset::rptr@)
			{
				address token_account = kvm::get<address>(uint8(0));
				return token_account.call<uint256>("uint256 balance_of(instrset::rptr@, const address&in)", tx::from());
			}));

			auto* deployment_ethereum2 = memory::init<transactions::deployment>();
			deployment_ethereum2->set_asset("ETH");
			deployment_ethereum2->set_program_calldata(decimal::zero(), bridge_program.substr(1, bridge_program.size() - 2), { format::variable(token_contract.get_address()) });
			deployment_ethereum2->sign_program(bridge_contract.secret_key);
			VI_PANIC(deployment_ethereum2->sign(user1.secret_key, user1_nonce++, decimal::zero()), "deployment not signed");
			transactions.push_back(deployment_ethereum2);
		}
		static void account_program_invocation(vector<uptr<ledger::transaction>>& transactions, vector<account>& users)
		{
			auto& [user1, user1_nonce] = users[0];
			auto& [user2, user2_nonce] = users[1];
			ledger::wallet token_contract = ledger::wallet::from_seed(string("token") + string((char*)user1.secret_key, sizeof(user1.secret_key)));
			auto* invocation_ethereum1 = memory::init<transactions::invocation>();
			invocation_ethereum1->set_asset("ETH");
			invocation_ethereum1->set_calldata(algorithm::encoding::to_subaddress(token_contract.public_key_hash), decimal::zero(), "transfer", { format::variable(std::string_view((char*)user2.public_key_hash, sizeof(user2.public_key_hash))), format::variable(250000u) });
			VI_PANIC(invocation_ethereum1->sign(user1.secret_key, user1_nonce++, decimal::zero()), "invocation not signed");
			transactions.push_back(invocation_ethereum1);

			auto* invocation_ethereum2 = memory::init<transactions::invocation>();
			invocation_ethereum2->set_asset("ETH");
			invocation_ethereum2->set_calldata(algorithm::encoding::to_subaddress(token_contract.public_key_hash), decimal::zero(), "info", { });
			VI_PANIC(invocation_ethereum2->sign(user1.secret_key, user1_nonce++, decimal::zero()), "invocation not signed");
			transactions.push_back(invocation_ethereum2);

			ledger::wallet bridge_contract = ledger::wallet::from_seed(string("bridge") + string((char*)user1.secret_key, sizeof(user1.secret_key)));
			auto* invocation_bitcoin = memory::init<transactions::invocation>();
			invocation_bitcoin->set_asset("BTC");
			invocation_bitcoin->set_calldata(algorithm::encoding::to_subaddress(bridge_contract.public_key_hash, "123456"), decimal::zero(), "balance_of_test_token", { });
			VI_PANIC(invocation_bitcoin->sign(user1.secret_key, user1_nonce++, decimal::zero()), "invocation not signed");
			transactions.push_back(invocation_bitcoin);
		}
		static void validator_registration_full(vector<uptr<ledger::transaction>>& transactions, vector<account>& users)
		{
			auto& [user1, user1_nonce] = users[0];
			auto& [user2, user2_nonce] = users[1];
			auto* certification_user1 = memory::init<transactions::certification>();
			certification_user1->set_asset("BTC");
			certification_user1->enable_block_production();
			certification_user1->allocate_attestation_stake(algorithm::asset::id_of("ETH"), decimal::zero());
			certification_user1->allocate_attestation_stake(algorithm::asset::id_of("XRP"), decimal::zero());
			certification_user1->allocate_attestation_stake(algorithm::asset::id_of("BTC"), decimal::zero());
			certification_user1->allocate_participation_stake(algorithm::asset::id_of("ETH"), decimal::zero());
			certification_user1->allocate_participation_stake(algorithm::asset::id_of("XRP"), decimal::zero());
			certification_user1->allocate_participation_stake(algorithm::asset::id_of("BTC"), decimal::zero());
			VI_PANIC(certification_user1->sign(user1.secret_key, user1_nonce++, decimal::zero()), "certification not signed");
			transactions.push_back(certification_user1);

			auto* certification_user2 = memory::init<transactions::certification>();
			certification_user2->set_asset("BTC");
			certification_user2->enable_block_production();
			certification_user2->allocate_attestation_stake(algorithm::asset::id_of("ETH"), decimal::zero());
			certification_user2->allocate_attestation_stake(algorithm::asset::id_of("XRP"), decimal::zero());
			certification_user2->allocate_attestation_stake(algorithm::asset::id_of("BTC"), decimal::zero());
			certification_user2->allocate_participation_stake(algorithm::asset::id_of("ETH"), decimal::zero());
			certification_user2->allocate_participation_stake(algorithm::asset::id_of("XRP"), decimal::zero());
			certification_user2->allocate_participation_stake(algorithm::asset::id_of("BTC"), decimal::zero());
			VI_PANIC(certification_user2->sign(user2.secret_key, user2_nonce++, decimal::zero()), "certification not signed");
			transactions.push_back(certification_user2);
		}
		static void validator_registration_partial(vector<uptr<ledger::transaction>>& transactions, vector<account>& users)
		{
			auto& [user1, user1_nonce] = users[0];
			auto* certification_user1 = memory::init<transactions::certification>();
			certification_user1->set_asset("BTC");
			certification_user1->enable_block_production();
			certification_user1->allocate_attestation_stake(algorithm::asset::id_of("ETH"), decimal::zero());
			certification_user1->allocate_attestation_stake(algorithm::asset::id_of("XRP"), decimal::zero());
			certification_user1->allocate_attestation_stake(algorithm::asset::id_of("BTC"), decimal::zero());
			certification_user1->allocate_participation_stake(algorithm::asset::id_of("ETH"), decimal::zero());
			certification_user1->allocate_participation_stake(algorithm::asset::id_of("XRP"), decimal::zero());
			certification_user1->allocate_participation_stake(algorithm::asset::id_of("BTC"), decimal::zero());
			VI_PANIC(certification_user1->sign(user1.secret_key, user1_nonce++, decimal::zero()), "certification not signed");
			transactions.push_back(certification_user1);
		}
		static void validator_enable_validator(vector<uptr<ledger::transaction>>& transactions, vector<account>& users, size_t user_id)
		{
			auto& [user1, user1_nonce] = users[user_id];
			auto* certification_user1 = memory::init<transactions::certification>();
			certification_user1->set_asset("BTC");
			certification_user1->enable_block_production();
			certification_user1->allocate_attestation_stake(algorithm::asset::id_of("ETH"), decimal::zero());
			certification_user1->allocate_attestation_stake(algorithm::asset::id_of("XRP"), decimal::zero());
			certification_user1->allocate_attestation_stake(algorithm::asset::id_of("BTC"), decimal::zero());
			certification_user1->allocate_participation_stake(algorithm::asset::id_of("ETH"), decimal::zero());
			certification_user1->allocate_participation_stake(algorithm::asset::id_of("XRP"), decimal::zero());
			certification_user1->allocate_participation_stake(algorithm::asset::id_of("BTC"), decimal::zero());
			VI_PANIC(certification_user1->sign(user1.secret_key, user1_nonce++, decimal::zero()), "certification not signed");
			transactions.push_back(certification_user1);
		}
		static void validator_disable_validator(vector<uptr<ledger::transaction>>& transactions, vector<account>& users, size_t user_id)
		{
			auto& [user1, user1_nonce] = users[user_id];
			auto* certification_user1 = memory::init<transactions::certification>();
			certification_user1->set_asset("BTC");
			certification_user1->disable_block_production();
			certification_user1->disable_attestation(algorithm::asset::id_of("ETH"));
			certification_user1->disable_attestation(algorithm::asset::id_of("XRP"));
			certification_user1->disable_attestation(algorithm::asset::id_of("BTC"));
			certification_user1->disable_participation(algorithm::asset::id_of("ETH"));
			certification_user1->disable_participation(algorithm::asset::id_of("XRP"));
			certification_user1->disable_participation(algorithm::asset::id_of("BTC"));
			VI_PANIC(certification_user1->sign(user1.secret_key, user1_nonce++, decimal::zero()), "certification not signed");
			transactions.push_back(certification_user1);
		}
		static void depository_registration_full(vector<uptr<ledger::transaction>>& transactions, vector<account>& users)
		{
			auto& [user1, user1_nonce] = users[0];
			auto& [user2, user2_nonce] = users[1];
			auto* depository_adjustment_ethereum1 = memory::init<transactions::depository_adjustment>();
			depository_adjustment_ethereum1->set_asset("ETH");
			depository_adjustment_ethereum1->set_reward(0.0012, 0.0012);
			depository_adjustment_ethereum1->set_security(2, true, true);
			VI_PANIC(depository_adjustment_ethereum1->sign(user2.secret_key, user2_nonce++, decimal::zero()), "depository adjustment not signed");
			transactions.push_back(depository_adjustment_ethereum1);

			auto* depository_adjustment_ethereum = memory::init<transactions::depository_adjustment>();
			depository_adjustment_ethereum->set_asset("ETH");
			depository_adjustment_ethereum->set_reward(0.0, 0.0);
			depository_adjustment_ethereum->set_security(2, true, true);
			VI_PANIC(depository_adjustment_ethereum->sign(user1.secret_key, user1_nonce++, decimal::zero()), "depository adjustment not signed");
			transactions.push_back(depository_adjustment_ethereum);

			auto* depository_adjustment_ripple = memory::init<transactions::depository_adjustment>();
			depository_adjustment_ripple->set_asset("XRP");
			depository_adjustment_ripple->set_reward(1.0, 1.0);
			depository_adjustment_ripple->set_security(2, true, true);
			VI_PANIC(depository_adjustment_ripple->sign(user2.secret_key, user2_nonce++, decimal::zero()), "depository adjustment not signed");
			transactions.push_back(depository_adjustment_ripple);

			auto* depository_adjustment_bitcoin = memory::init<transactions::depository_adjustment>();
			depository_adjustment_bitcoin->set_asset("BTC");
			depository_adjustment_bitcoin->set_reward(0.000025, 0.000025);
			depository_adjustment_bitcoin->set_security(2, true, true);
			VI_PANIC(depository_adjustment_bitcoin->sign(user2.secret_key, user2_nonce++, decimal::zero()), "depository adjustment not signed");
			transactions.push_back(depository_adjustment_bitcoin);
		}
		static void depository_registration_partial(vector<uptr<ledger::transaction>>& transactions, vector<account>& users)
		{
			auto& [user1, user1_nonce] = users[0];
			auto* depository_adjustment_bitcoin = memory::init<transactions::depository_adjustment>();
			depository_adjustment_bitcoin->set_asset("BTC");
			depository_adjustment_bitcoin->set_reward(0.00001, 0.000025);
			depository_adjustment_bitcoin->set_security(1, true, true);
			VI_PANIC(depository_adjustment_bitcoin->sign(user1.secret_key, user1_nonce++, decimal::zero()), "depository adjustment not signed");
			transactions.push_back(depository_adjustment_bitcoin);
		}
		static void depository_account_registration_full(vector<uptr<ledger::transaction>>& transactions, vector<account>& users)
		{
			auto& [user1, user1_nonce] = users[0];
			auto& [user2, user2_nonce] = users[1];
			auto* depository_account_ethereum1 = memory::init<transactions::depository_account>();
			depository_account_ethereum1->set_asset("ETH");
			depository_account_ethereum1->set_routing_address("0xCa0dfDdBb1cBD7B5A08E9173D9bbE5722138d4d5");
			depository_account_ethereum1->set_manager(user1.public_key_hash);
			VI_PANIC(depository_account_ethereum1->sign(user1.secret_key, user1_nonce++, decimal::zero()), "account not signed");
			transactions.push_back(depository_account_ethereum1);

			auto* depository_account_ethereum2 = memory::init<transactions::depository_account>();
			depository_account_ethereum2->set_asset("ETH");
			depository_account_ethereum2->set_manager(user2.public_key_hash);
			VI_PANIC(depository_account_ethereum2->sign(user2.secret_key, user2_nonce++, decimal::zero()), "account not signed");
			transactions.push_back(depository_account_ethereum2);

			auto* depository_account_ripple = memory::init<transactions::depository_account>();
			depository_account_ripple->set_asset("XRP");
			depository_account_ripple->set_routing_address("rUBqz2JiRCT3gYZBnm28y5ME7e5UpSm2ok");
			depository_account_ripple->set_manager(user2.public_key_hash);
			VI_PANIC(depository_account_ripple->sign(user1.secret_key, user1_nonce++, decimal::zero()), "account not signed");
			transactions.push_back(depository_account_ripple);

			auto* depository_account_bitcoin = memory::init<transactions::depository_account>();
			depository_account_bitcoin->set_asset("BTC");
			depository_account_bitcoin->set_routing_address("mmtubFoJvXrBuBUQFf1RrowXUbsiPDYnYS");
			depository_account_bitcoin->set_manager(user2.public_key_hash);
			VI_PANIC(depository_account_bitcoin->sign(user1.secret_key, user1_nonce++, decimal::zero()), "account not signed");
			transactions.push_back(depository_account_bitcoin);
		}
		static void depository_account_registration_partial(vector<uptr<ledger::transaction>>& transactions, vector<account>& users)
		{
			auto& [user1, user1_nonce] = users[0];
			auto* depository_account_bitcoin = memory::init<transactions::depository_account>();
			depository_account_bitcoin->set_asset("BTC");
			depository_account_bitcoin->set_routing_address("mmtubFoJvXrBuBUQFf1RrowXUbsiPDYnYS");
			depository_account_bitcoin->set_manager(user1.public_key_hash);
			VI_PANIC(depository_account_bitcoin->sign(user1.secret_key, user1_nonce++, decimal::zero()), "account not signed");
			transactions.push_back(depository_account_bitcoin);
		}
		static void depository_transaction_registration_full(vector<uptr<ledger::transaction>>& transactions, vector<account>& users)
		{
			auto& [user1, user1_nonce] = users[0];
			auto& [user2, user2_nonce] = users[1];
			auto context = ledger::transaction_context();
			auto manager_addresses = *context.get_witness_accounts_by_purpose(user2.public_key_hash, states::witness_account::account_type::depository, 0, 128);
			auto owner_addresses = *context.get_witness_accounts_by_purpose(user1.public_key_hash, states::witness_account::account_type::depository, 0, 128);
			auto address_ethereum = std::find_if(manager_addresses.begin(), manager_addresses.end(), [](states::witness_account& item) { return item.asset == algorithm::asset::id_of("ETH"); });
			auto address_ripple = std::find_if(owner_addresses.begin(), owner_addresses.end(), [](states::witness_account& item) { return item.asset == algorithm::asset::id_of("XRP"); });
			auto address_bitcoin = std::find_if(owner_addresses.begin(), owner_addresses.end(), [](states::witness_account& item) { return item.asset == algorithm::asset::id_of("BTC"); });
			VI_PANIC(address_ethereum != manager_addresses.end(), "ethereum depository address not found");
			VI_PANIC(address_ripple != owner_addresses.end(), "ripple depository address not found");
			VI_PANIC(address_bitcoin != owner_addresses.end(), "bitcoin depository address not found");

			auto* depository_transaction_ethereum = memory::init<transactions::depository_transaction>();
			depository_transaction_ethereum->set_asset("ETH");
			depository_transaction_ethereum->set_finalized_witness(14977180,
				"0x2bc2c98682f1b8fea2031e8f3f56494cd778da9d042da8439fb698d41bf061ea",
				{ warden::value_transfer(depository_transaction_ethereum->asset, "0xCa0dfDdBb1cBD7B5A08E9173D9bbE5722138d4d5", 100) },
				{ warden::value_transfer(depository_transaction_ethereum->asset, address_ethereum->addresses.begin()->second, 100) });
			transactions.push_back(depository_transaction_ethereum);

			auto* depository_transaction_ripple = memory::init<transactions::depository_transaction>();
			depository_transaction_ripple->set_asset("XRP");
			depository_transaction_ripple->set_finalized_witness(88546830,
				"2618D20B801AF96DD060B34228E2594E30AFB7B33E335A8C60199B6CF8B0A69F",
				{ warden::value_transfer(depository_transaction_ripple->asset, "rUBqz2JiRCT3gYZBnm28y5ME7e5UpSm2ok", 1000) },
				{ warden::value_transfer(depository_transaction_ripple->asset, address_ripple->addresses.begin()->second, 1000) });
			transactions.push_back(depository_transaction_ripple);

			auto* depository_transaction_bitcoin = memory::init<transactions::depository_transaction>();
			depository_transaction_bitcoin->set_asset("BTC");
			depository_transaction_bitcoin->set_finalized_witness(846982,
				"57638131d9af3033a5e20b753af254e1e8321b2039f16dfd222f6b1117b5c69d",
				{ warden::value_transfer(depository_transaction_bitcoin->asset, "mmtubFoJvXrBuBUQFf1RrowXUbsiPDYnYS", 1.0) },
				{ warden::value_transfer(depository_transaction_bitcoin->asset, address_bitcoin->addresses.begin()->second, 1.0) });
			transactions.push_back(depository_transaction_bitcoin);
		}
		static void depository_transaction_registration_partial(vector<uptr<ledger::transaction>>& transactions, vector<account>& users)
		{
			auto& [user1, user1_nonce] = users[0];
			auto context = ledger::transaction_context();
			auto owner_addresses = *context.get_witness_accounts_by_purpose(user1.public_key_hash, states::witness_account::account_type::depository, 0, 128);
			auto address_bitcoin = std::find_if(owner_addresses.begin(), owner_addresses.end(), [](states::witness_account& item) { return item.asset == algorithm::asset::id_of("BTC"); });
			VI_PANIC(address_bitcoin != owner_addresses.end(), "bitcoin depository address not found");

			auto* depository_transaction_bitcoin = memory::init<transactions::depository_transaction>();
			depository_transaction_bitcoin->set_asset("BTC");
			depository_transaction_bitcoin->set_finalized_witness(846982,
				"57638131d9af3033a5e20b753af254e1e8321b2039f16dfd222f6b1117b5c69d",
				{ warden::value_transfer(depository_transaction_bitcoin->asset, "mmtubFoJvXrBuBUQFf1RrowXUbsiPDYnYS", 1.0) },
				{ warden::value_transfer(depository_transaction_bitcoin->asset, address_bitcoin->addresses.begin()->second, 1.0) });
			transactions.push_back(depository_transaction_bitcoin);
		}
		static void depository_regrouping(vector<uptr<ledger::transaction>>& transactions, vector<account>& users)
		{
			auto& [user2, user2_nonce] = users[1];
			auto mempool = storages::mempoolstate(__func__);
			auto accounts = mempool.get_group_accounts(nullptr, 0, 128);
			if (accounts && !accounts->empty())
			{
				auto user2_address = algorithm::pubkeyhash_t(user2.public_key_hash);
				for (auto& account : *accounts)
				{
					if (account.group.find(user2_address) != account.group.end())
					{
						auto* depository_regrouping_ethereum = memory::init<transactions::depository_regrouping>();
						depository_regrouping_ethereum->asset = account.asset;
						depository_regrouping_ethereum->migrate(account.asset, account.manager, account.owner);
						VI_PANIC(depository_regrouping_ethereum->sign(user2.secret_key, user2_nonce++, decimal::zero()), "migration not signed");
						transactions.push_back(depository_regrouping_ethereum);
					}
				}
			}
		}
		static void depository_withdrawal_stage_1(vector<uptr<ledger::transaction>>& transactions, vector<account>& users)
		{
			auto& [user1, user1_nonce] = users[0];
			auto& [user2, user2_nonce] = users[1];
			auto* depository_withdrawal_ethereum = memory::init<transactions::depository_withdrawal>();
			depository_withdrawal_ethereum->set_asset("ETH");
			depository_withdrawal_ethereum->set_from_manager(user2.public_key_hash);
			depository_withdrawal_ethereum->set_to_manager(user1.public_key_hash);
			VI_PANIC(depository_withdrawal_ethereum->sign(user2.secret_key, user2_nonce++, decimal::zero()), "depository migration not signed");
			transactions.push_back(depository_withdrawal_ethereum);
		}
		static void depository_withdrawal_stage_2(vector<uptr<ledger::transaction>>& transactions, vector<account>& users)
		{
			auto& [user1, user1_nonce] = users[0];
			auto& [user2, user2_nonce] = users[1];
			auto context = ledger::transaction_context();
			auto* withdrawal_ethereum = memory::init<transactions::depository_withdrawal>();
			withdrawal_ethereum->set_asset("ETH");
			withdrawal_ethereum->set_from_manager(user1.public_key_hash);
			withdrawal_ethereum->set_to("0xCa0dfDdBb1cBD7B5A08E9173D9bbE5722138d4d5", context.get_account_balance(algorithm::asset::id_of("ETH"), user1.public_key_hash).expect("user balance not valid").get_balance());
			VI_PANIC(withdrawal_ethereum->sign(user1.secret_key, user1_nonce++, decimal::zero()), "withdrawal not signed");
			transactions.push_back(withdrawal_ethereum);

			auto* withdrawal_ripple = memory::init<transactions::depository_withdrawal>();
			withdrawal_ripple->set_asset("XRP");
			withdrawal_ripple->set_from_manager(user2.public_key_hash);
			withdrawal_ripple->set_to("rUBqz2JiRCT3gYZBnm28y5ME7e5UpSm2ok", context.get_account_balance(algorithm::asset::id_of("XRP"), user1.public_key_hash).expect("user balance not valid").get_balance());
			VI_PANIC(withdrawal_ripple->sign(user1.secret_key, user1_nonce++, decimal::zero()), "withdrawal not signed");
			transactions.push_back(withdrawal_ripple);

			auto* withdrawal_bitcoin = memory::init<transactions::depository_withdrawal>();
			withdrawal_bitcoin->set_asset("BTC");
			withdrawal_bitcoin->set_from_manager(user2.public_key_hash);
			withdrawal_bitcoin->set_to("mmtubFoJvXrBuBUQFf1RrowXUbsiPDYnYS", context.get_account_balance(algorithm::asset::id_of("BTC"), user1.public_key_hash).expect("user balance not valid").get_balance());
			VI_PANIC(withdrawal_bitcoin->sign(user1.secret_key, user1_nonce++, decimal::zero()), "withdrawal not signed");
			transactions.push_back(withdrawal_bitcoin);
		}
		static void depository_withdrawal_stage_3(vector<uptr<ledger::transaction>>& transactions, vector<account>& users)
		{
			auto& [user1, user1_nonce] = users[0];
			auto& [user2, user2_nonce] = users[1];
			auto context = ledger::transaction_context();
			auto* withdrawal_ethereum = memory::init<transactions::depository_withdrawal>();
			withdrawal_ethereum->set_asset("ETH");
			withdrawal_ethereum->set_from_manager(user1.public_key_hash);
			withdrawal_ethereum->set_to("0x89a0181659bd280836A2d33F57e3B5Dfa1a823CE", context.get_account_balance(algorithm::asset::id_of("ETH"), user2.public_key_hash).expect("user balance not valid").get_balance());
			VI_PANIC(withdrawal_ethereum->sign(user2.secret_key, user2_nonce++, decimal::zero()), "withdrawal not signed");
			transactions.push_back(withdrawal_ethereum);

			auto* withdrawal_ripple = memory::init<transactions::depository_withdrawal>();
			withdrawal_ripple->set_asset("XRP");
			withdrawal_ripple->set_from_manager(user2.public_key_hash);
			withdrawal_ripple->set_to("rJGb4etn9GSwNHYVu7dNMbdiVgzqxaTSUG", context.get_account_balance(algorithm::asset::id_of("XRP"), user2.public_key_hash).expect("user balance not valid").get_balance());
			VI_PANIC(withdrawal_ripple->sign(user2.secret_key, user2_nonce++, decimal::zero()), "withdrawal not signed");
			transactions.push_back(withdrawal_ripple);

			auto* withdrawal_bitcoin = memory::init<transactions::depository_withdrawal>();
			withdrawal_bitcoin->set_asset("BTC");
			withdrawal_bitcoin->set_from_manager(user2.public_key_hash);
			withdrawal_bitcoin->set_to("bcrt1p2w7gkghj7arrjy4c45kh7450458hr8dv9pu9576lx08uuh4je7eqgskm9v", context.get_account_balance(algorithm::asset::id_of("BTC"), user2.public_key_hash).expect("user balance not valid").get_balance());
			VI_PANIC(withdrawal_bitcoin->sign(user2.secret_key, user2_nonce++, decimal::zero()), "withdrawal not signed");
			transactions.push_back(withdrawal_bitcoin);
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
		uptr<schema> data = var::set::object();
		algorithm::pubkeyhash owner;
		algorithm::hashing::hash160((uint8_t*)"publickeyhash", 13, owner);
		uint256_t asset = algorithm::asset::id_of("BTC");
		uint64_t block_number = 1;
		uint64_t block_nonce = 1;

		new_serialization_comparison<warden::wallet_link>(*data);
		new_serialization_comparison<warden::coin_utxo>(*data);
		new_serialization_comparison<warden::computed_transaction>(*data);
		new_serialization_comparison<warden::prepared_transaction>(*data);
		new_serialization_comparison<warden::finalized_transaction>(*data);
		new_serialization_comparison<ledger::receipt>(*data);
		new_serialization_comparison<ledger::wallet>(*data);
		new_serialization_comparison<ledger::validator>(*data);
		new_serialization_comparison<ledger::block_transaction>(*data);
		new_serialization_comparison<ledger::block_header>(*data);
		new_serialization_comparison<ledger::block>(*data);
		new_serialization_comparison<ledger::block_proof>(*data, ledger::block_header(), (ledger::block_header*)nullptr);
		new_serialization_comparison<states::account_nonce>(*data, owner, block_number++, block_nonce++);
		new_serialization_comparison<states::account_program>(*data, owner, block_number++, block_nonce++);
		new_serialization_comparison<states::account_uniform>(*data, owner, std::string_view(), block_number++, block_nonce++);
		new_serialization_comparison<states::account_multiform>(*data, owner, std::string_view(), std::string_view(), block_number++, block_nonce++);
		new_serialization_comparison<states::account_balance>(*data, owner, asset, block_number++, block_nonce++);
		new_serialization_comparison<states::validator_production>(*data, owner, block_number++, block_nonce++);
		new_serialization_comparison<states::validator_participation>(*data, owner, asset, block_number++, block_nonce++);
		new_serialization_comparison<states::validator_attestation>(*data, owner, asset, block_number++, block_nonce++);
		new_serialization_comparison<states::depository_reward>(*data, owner, asset, block_number++, block_nonce++);
		new_serialization_comparison<states::depository_balance>(*data, owner, asset, block_number++, block_nonce++);
		new_serialization_comparison<states::depository_policy>(*data, owner, asset, block_number++, block_nonce++);
		new_serialization_comparison<states::depository_account>(*data, owner, asset, owner, block_number++, block_nonce++);
		new_serialization_comparison<states::witness_program>(*data, std::string_view(), block_number++, block_nonce++);
		new_serialization_comparison<states::witness_event>(*data, asset, block_number++, block_nonce++);
		new_serialization_comparison<states::witness_account>(*data, owner, asset, address_map(), block_number++, block_nonce++);
		new_serialization_comparison<states::witness_transaction>(*data, asset, std::string_view(), block_number++, block_nonce++);
		new_serialization_comparison<transactions::transfer>(*data);
		new_serialization_comparison<transactions::deployment>(*data);
		new_serialization_comparison<transactions::invocation>(*data);
		new_serialization_comparison<transactions::rollup>(*data);
		new_serialization_comparison<transactions::certification>(*data);
		new_serialization_comparison<transactions::depository_account>(*data);
		new_serialization_comparison<transactions::depository_account_finalization>(*data);
		new_serialization_comparison<transactions::depository_withdrawal>(*data);
		new_serialization_comparison<transactions::depository_withdrawal_finalization>(*data);
		new_serialization_comparison<transactions::depository_transaction>(*data);
		new_serialization_comparison<transactions::depository_adjustment>(*data);
		new_serialization_comparison<transactions::depository_regrouping>(*data);
		new_serialization_comparison<transactions::depository_regrouping_preparation>(*data);
		new_serialization_comparison<transactions::depository_regrouping_commitment>(*data);
		new_serialization_comparison<transactions::depository_regrouping_finalization>(*data);

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
		algorithm::recpubsig message_signature;
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
		info->set("secret_key", var::string(encoded_secret_key));
		info->set("public_key", var::string(encoded_public_key));
		info->set("address", var::string(encoded_public_key_hash));
		info->set("message", var::string(message));
		info->set("message_hash", var::string(encoded_message_hash));
		info->set("signature", var::string(encoded_message_signature));
		info->set("recover_public_key", var::string(encoded_recover_public_key));
		info->set("recover_address", var::string(encoded_recover_public_key_hash));
		term->jwrite_line(*info);

		VI_PANIC(algorithm::signing::verify_mnemonic(mnemonic), "bad mnemonic phrase");
		VI_PANIC(algorithm::signing::verify_secret_key(secret_key), "bad secret key");
		VI_PANIC(algorithm::signing::verify_public_key(public_key), "bad public key");
		VI_PANIC(algorithm::signing::verify_address(encoded_public_key_hash), "bad address");
		VI_PANIC(verifies, "bad signature");
		VI_PANIC(recovers_public_key && encoded_recover_public_key == encoded_public_key, "failed to recover public key from signature");
		VI_PANIC(recovers_public_key_hash && encoded_recover_public_key_hash == encoded_public_key_hash, "failed to recover address from signature");
	}
	/* wallet cryptography */
	static void cryptography_wallet()
	{
		auto* term = console::get();
		auto wallet = ledger::wallet::from_seed();
		term->jwrite_line(*wallet.as_schema());

		VI_PANIC(algorithm::signing::verify_secret_key(wallet.secret_key), "bad secret key");
		VI_PANIC(algorithm::signing::verify_public_key(wallet.public_key), "bad public key");
		VI_PANIC(algorithm::signing::verify_address(wallet.get_address()), "bad address");
	}
	/* wallet encryption cryptography */
	static void cryptography_wallet_encryption()
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
		auto ciphertext1 = user1.seal_message(message_from_user1, cipher_public_key2, *crypto::random_bytes(64)).expect("failed to encrypt the message to user 2");
		auto plaintext1 = user2.open_message(nonce2, ciphertext1).expect("failed to decrypt the message from user 1");
		auto ciphertext2 = user2.seal_message(message_from_user2, cipher_public_key1, *crypto::random_bytes(64)).expect("failed to encrypt the message to user 1");
		auto plaintext2 = user1.open_message(nonce1, ciphertext2).expect("failed to decrypt the message from user 2");

		uptr<schema> data = var::set::object();
		auto* user1_wallet_data = data->set("user1_wallet", user1.as_schema().reset());
		auto* user1_wallet_message_data = user1_wallet_data->set("message");
		user1_wallet_message_data->set("cipher_nonce", algorithm::encoding::serialize_uint256(nonce1));
		user1_wallet_message_data->set("cipher_secret_key", var::string(format::util::encode_0xhex(std::string_view((char*)cipher_secret_key1, sizeof(cipher_secret_key1)))));
		user1_wallet_message_data->set("cipher_public_key", var::string(format::util::encode_0xhex(std::string_view((char*)cipher_public_key1, sizeof(cipher_public_key1)))));
		user1_wallet_message_data->set("ciphertext_to_user2_wallet", var::string(format::util::encode_0xhex(ciphertext1)));
		user1_wallet_message_data->set("plaintext_from_user2_wallet", var::string(plaintext2));
		auto* user2_wallet_data = data->set("user2_wallet", user2.as_schema().reset());
		auto* user2_wallet_message_data = user2_wallet_data->set("message");
		user2_wallet_message_data->set("cipher_nonce", algorithm::encoding::serialize_uint256(nonce2));
		user2_wallet_message_data->set("cipher_secret_key", var::string(format::util::encode_0xhex(std::string_view((char*)cipher_secret_key2, sizeof(cipher_secret_key2)))));
		user2_wallet_message_data->set("cipher_public_key", var::string(format::util::encode_0xhex(std::string_view((char*)cipher_public_key2, sizeof(cipher_public_key2)))));
		user2_wallet_message_data->set("ciphertext_to_user2_wallet", var::string(format::util::encode_0xhex(ciphertext2)));
		user2_wallet_message_data->set("plaintext_from_user2_wallet", var::string(plaintext1));
		term->jwrite_line(*data);
	}
	/* wallet address cryptography */
	static void cryptography_wallet_address()
	{
		auto* term = console::get();
		auto wallet = ledger::wallet::from_seed();
		auto test = ledger::wallet::from_seed("123456");
		auto address = wallet.get_address();
		auto subaddress_from_data = wallet.get_subaddress("123456");
		auto subaddress_from_hash = wallet.get_subaddress(test.public_key_hash);

		auto data = uptr(var::set::object());
		data->set("address", algorithm::signing::serialize_address(wallet.public_key_hash));
		data->set("subaddress_from_data", algorithm::signing::serialize_subaddress(wallet.public_key_hash, "123456"));
		data->set("subaddress_from_hash", algorithm::signing::serialize_subaddress(wallet.public_key_hash, test.public_key_hash));
		term->jwrite_line(*data);

		algorithm::pubkeyhash public_key_hash;
		algorithm::signing::decode_address(address, public_key_hash);

		algorithm::pubkeyhash public_key_hash_from_data;
		algorithm::signing::decode_address(subaddress_from_data, public_key_hash_from_data);

		algorithm::pubkeyhash public_key_hash_from_hash;
		algorithm::signing::decode_address(subaddress_from_hash, public_key_hash_from_hash);

		VI_PANIC(!memcmp(wallet.public_key_hash, public_key_hash, sizeof(public_key_hash)) && algorithm::signing::verify_address(address), "bad address 1");
		VI_PANIC(!memcmp(wallet.public_key_hash, public_key_hash_from_data, sizeof(public_key_hash_from_data)) && algorithm::signing::verify_address(subaddress_from_data), "bad address 2");
		VI_PANIC(!memcmp(wallet.public_key_hash, public_key_hash_from_hash, sizeof(public_key_hash_from_hash)) && algorithm::signing::verify_address(subaddress_from_hash), "bad address 3");
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

		auto tx = transactions::transfer();
		tx.gas_limit = ledger::block::get_gas_limit();
		tx.set_asset("ETH");
		tx.set_to(algorithm::encoding::to_subaddress(users[1].wallet.public_key_hash), decimal("13.539899"));
		VI_PANIC(tx.sign(users[0].wallet.secret_key, users[0].nonce++), "transfer not signed");

		auto tx_blob = tx.as_message().data;
		auto tx_body = format::stream(tx_blob);
		auto tx_copy = uptr<ledger::transaction>(transactions::resolver::from_stream(tx_body));
		auto tx_info = tx.as_schema();
		algorithm::pubkeyhash recover_public_key_hash = { 0 };
		tx_info->set("raw_data", var::string(format::util::encode_0xhex(tx_blob)));

		auto stream = tx.as_message();
		format::variables vars;
		format::variables_util::deserialize_flat_from(stream, &vars);
		tx_info->set("var_data", format::variables_util::serialize(vars));
		tx_info->set("asset_id", algorithm::asset::serialize(algorithm::asset::id_of("ETH", "USDT", "0xdAC17F958D2ee523a2206206994597C13D831ec7")));
		term->jwrite_line(*tx_info);

		VI_PANIC(tx.recover_hash(recover_public_key_hash) && !memcmp(wallet.public_key_hash, recover_public_key_hash, sizeof(recover_public_key_hash)), "failed to recover the public key hash from signature");
		VI_PANIC(tx.verify(wallet.public_key), "failed to verify the signature");
		VI_PANIC(tx_copy && tx_copy->load(tx_body) && tx_copy->as_message().data == tx_blob, "failed to serialize/deserialize the transaction");
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
	/* warden wallets cryptography */
	static void cryptography_multichain_wallet()
	{
		auto* term = console::get();
		auto* server = nss::server_node::get();
		auto user = ledger::wallet::from_seed("0000000");
		for (auto& asset : server->get_assets())
		{
			auto wallet = *server->compute_wallet(asset, 123456);
			term->jwrite_line(*wallet.as_schema());
		}
	}
	/* multi-party wallet keypair and signature generation */
	static void cryptography_multichain_mpc()
	{
		auto* term = console::get();
		vector<participant> participants;
		participants.resize(8);

		for (auto& [alg, alg_name] :
			{
				std::make_pair(algorithm::composition::type::ed25519, std::string_view("ed25519")),
				std::make_pair(algorithm::composition::type::ed25519_clsag, std::string_view("ed25519_clsag")),
				std::make_pair(algorithm::composition::type::secp256k1, std::string_view("secp256k1")),
				std::make_pair(algorithm::composition::type::schnorr, std::string_view("schnorr")),
				std::make_pair(algorithm::composition::type::schnorr_taproot, std::string_view("schnorr_taproot"))
			})
		{
			auto seckey_size = algorithm::composition::size_of_secret_key(alg);
			auto pubkey_size = algorithm::composition::size_of_public_key(alg);
			auto signature_size = algorithm::composition::size_of_signature(alg);

			for (size_t i = 0; i < participants.size(); i++)
			{
				auto& share = participants[i];
				share.seed = algorithm::hashing::hash256i("seed" + to_string(i));
				algorithm::composition::derive_keypair(alg, share.seed, &share.keypair).expect("failed to derive a keypair share");

				auto participant_data = uptr(var::set::object());
				participant_data->set("participant_id", var::integer(i));
				participant_data->set("share_seed", var::string(algorithm::encoding::encode_0xhex256(share.seed)));
				participant_data->set("share_secret_key", var::string(format::util::encode_0xhex(std::string_view((char*)share.keypair.secret_key, seckey_size))));
				participant_data->set("share_public_key", var::string(format::util::encode_0xhex(std::string_view((char*)share.keypair.public_key, pubkey_size))));
				term->jwrite_line(*participant_data);
			}

			algorithm::composition::cseckey mpc_secret_key = { 0 };
			for (size_t i = 0; i < participants.size(); i++)
			{
				auto& share = participants[i];
				algorithm::composition::accumulate_secret_key(alg, share.keypair.secret_key, mpc_secret_key).expect("failed to calculate cumulative secret key");
			}
			algorithm::composition::accumulate_secret_key(alg, nullptr, mpc_secret_key).expect("failed to finalize cumulative secret key");

			algorithm::composition::cpubkey mpc_public_key = { 0 };
			for (size_t i = 0; i < participants.size(); i++)
			{
				auto& share = participants[i];
				algorithm::composition::accumulate_public_key(alg, share.keypair.secret_key, mpc_public_key).expect("failed to calculate cumulative public key");
			}
			algorithm::composition::accumulate_public_key(alg, nullptr, mpc_public_key).expect("failed to finalize cumulative public key");

			std::string_view message = "Hello, World!";
			uint8_t message_hash[32];
			algorithm::hashing::hash256((uint8_t*)message.data(), message.size(), message_hash);

			algorithm::composition::cpubsig mpc_signature = { 0 };
			for (size_t i = 0; i < participants.size(); i++)
			{
				auto& share = participants[i];
				algorithm::composition::accumulate_signature(alg, message_hash, sizeof(message_hash), mpc_public_key, share.keypair.secret_key, mpc_signature).expect("failed to calculate cumulative signature");
			}
			algorithm::composition::accumulate_signature(alg, message_hash, sizeof(message_hash), mpc_public_key, nullptr, mpc_signature).expect("failed to finalize cumulative signature");

			auto mpc_data = uptr(var::set::object());
			mpc_data->set("message", var::string(message));
			mpc_data->set("message_hash", var::string(format::util::encode_0xhex(std::string_view((char*)message_hash, sizeof(message_hash)))));
			mpc_data->set("mpc_algorithm", var::string(alg_name));
			mpc_data->set("mpc_participants", var::integer(participants.size()));
			mpc_data->set("mpc_secret_key", var::string(format::util::encode_0xhex(std::string_view((char*)mpc_secret_key, seckey_size))));
			mpc_data->set("mpc_public_key", var::string(format::util::encode_0xhex(std::string_view((char*)mpc_public_key, pubkey_size))));
			mpc_data->set("mpc_signature", var::string(format::util::encode_0xhex(std::string_view((char*)mpc_signature, signature_size))));
			term->jwrite_line(*mpc_data);
		}
	}
	/* warden transaction generation test */
	static void cryptography_multichain_transaction()
	{
		auto* server = nss::server_node::get();
		auto* term = console::get();
		auto seed = uint256_t(123456);
		auto user = ledger::wallet::from_seed(seed.to_string());
		auto create_wallet = [&](const algorithm::asset_id& asset) -> nss::computed_wallet
		{
			auto wallet = *server->compute_wallet(asset, seed);
			for (auto& encoded_address : wallet.encoded_addresses)
				server->enable_link(asset, warden::wallet_link(user.public_key_hash, wallet.encoded_public_key, encoded_address.second)).expect("link activation error");
			return wallet;
		};
		auto validate_transaction = [&](const algorithm::asset_id& asset, const nss::computed_wallet& wallet, warden::prepared_transaction& prepared, const std::string_view& environment, const std::string_view& expected_calldata)
		{
			for (auto& input : prepared.inputs)
			{
				algorithm::composition::accumulate_signature(input.alg, input.message.data(), input.message.size(), input.public_key, wallet.secret_key, input.signature).expect("signature accumulation error");
				algorithm::composition::accumulate_signature(input.alg, input.message.data(), input.message.size(), input.public_key, nullptr, input.signature).expect("signature finalization error");
			}

			warden::finalized_transaction finalized = server->finalize_transaction(asset, std::move(prepared)).expect("prepared transaction finalization error");
			VI_PANIC(finalized.calldata == expected_calldata, "resulting calldata differs from expected calldata");
			term->fwrite_line("%s (%.*s) = %s", algorithm::asset::handle_of(asset).c_str(), (int)environment.size(), environment.data(), finalized.calldata.c_str());
		};
		use_clean_state([&]()
		{
			auto asset = algorithm::asset::id_of("BTC");
			auto options = var::set::array();
			options->push(var::string("p2pk"));
			options->push(var::string("p2sh_p2wpkh"));
			options->push(var::string("p2pkh"));
			options->push(var::string("p2wsh_p2pkh"));
			options->push(var::string("p2wpkh"));
			options->push(var::string("p2tr"));
			server->add_specifications(asset, options);

			auto wallet = create_wallet(asset);
			server->add_specifications(asset, nullptr);

			auto input_p2pkh_hash = codec::hex_decode("0x57e30b41a6d984cdb763145f32ad9678a9b2bfd0267e12d5d0474e97f7d077d0");
			warden::coin_utxo input_p2pkh;
			input_p2pkh.link = warden::wallet_link(user.public_key_hash, wallet.encoded_public_key, wallet.encoded_addresses[3]);
			input_p2pkh.transaction_id = "382940bfc9a1fe1f09a3fb8e1fda1b25b90dc2019ff5973b1d9d616e15b29840";
			input_p2pkh.index = 1;
			input_p2pkh.value = 0.1;

			auto input_p2sh_hash = codec::hex_decode("0xc4e23865424498b4d90c57dda4bea4718e1e6ed669cc00796afd864ac6de3606");
			warden::coin_utxo input_p2sh;
			input_p2sh.link = warden::wallet_link(user.public_key_hash, wallet.encoded_public_key, wallet.encoded_addresses[2]);
			input_p2sh.transaction_id = "3d7c1f8e03a73821517d2f0220fe3ecf82c2f55b94b724e5d5298c87070802a0";
			input_p2sh.value = 0.1;

			auto input_p2wpkh_hash_1 = codec::hex_decode("0xe79739ac82960be8bedb5175203bd65880b0c45c5c0286d54b5bc6eb4bac3898");
			warden::coin_utxo input_p2wpkh_1;
			input_p2wpkh_1.link = warden::wallet_link(user.public_key_hash, wallet.encoded_public_key, wallet.encoded_addresses[6]);
			input_p2wpkh_1.transaction_id = "5594c04289179bff0f434e5349fafbaa4d43da403b9dc7a637f5afe035b99729";
			input_p2wpkh_1.value = 0.1;

			auto input_p2tr_public_key = algorithm::composition::cpubkey_t(codec::hex_decode("0xb87e4bdf20eae22ef8a11583285b1da18ca003156f06f2dff845dfcdacf3382004c32a8b5fae170a7a0d28332a663b96f43d24ed4c9db30dfdd9d9d053d3d3e6"));
			auto input_p2tr_hash = codec::hex_decode("0x50cc324f902032625ba70fdfee889032a7ff4de1c7732dc3982b72c1ba2df8b5");
			warden::coin_utxo input_p2tr;
			input_p2tr.link = warden::wallet_link(user.public_key_hash, wallet.encoded_public_key, wallet.encoded_addresses[4]);
			input_p2tr.transaction_id = "988fcb7035c0f51688ddcfaf92ec8fdd0e9bda8b53aa3403bf096611147fb325";
			input_p2tr.value = 0.1;

			auto input_p2wpkh_hash_2 = codec::hex_decode("0x16a41f749d25f7ebae96aabd62207c2189ac3623b2ddee4560213a3563f81042");
			warden::coin_utxo input_p2wpkh_2;
			input_p2wpkh_2.link = warden::wallet_link(user.public_key_hash, wallet.encoded_public_key, wallet.encoded_addresses[6]);
			input_p2wpkh_2.transaction_id = "9b7a67a6a46f48f896c1de89d479d9d1f5b284809065671ff931c800e1041530";
			input_p2wpkh_2.value = 0.1;

			auto input_p2wsh_hash = codec::hex_decode("0x40cfd352d152929ada057d28c0e18f781a8b9ddb24df1b6381b0738c8f0ccbb9");
			warden::coin_utxo input_p2wsh;
			input_p2wsh.link = warden::wallet_link(user.public_key_hash, wallet.encoded_public_key, wallet.encoded_addresses[5]);
			input_p2wsh.transaction_id = "ccc7949d20241f04362c42e20125c83096a617b906e1d8123d1b8b08740c6025";
			input_p2wsh.index = 1;
			input_p2wsh.value = decimal("0.1001");

			auto input_p2pk_hash = codec::hex_decode("0xe665fd68a288da956f73810db79647a59dbbd6dafb0891f97364a0dfff520b2e");
			warden::coin_utxo input_p2pk;
			input_p2pk.link = warden::wallet_link(user.public_key_hash, wallet.encoded_public_key, wallet.encoded_addresses[1]);
			input_p2pk.transaction_id = "f0b0d2386cd578677df2380361410008d260fc827282904e54bdcb9e1d8cf62f";
			input_p2pk.index = 0;
			input_p2pk.value = decimal("0.0999");

			warden::coin_utxo output_p2wpkh;
			output_p2wpkh.link = warden::wallet_link::from_address("bcrt1q9ls8q57rsktvxn6krgjktd6jyukfpenyvd2sa3");
			output_p2wpkh.value = 0.65;

			warden::coin_utxo output_p2pkh;
			output_p2pkh.link = input_p2pkh.link;
			output_p2pkh.index = 1;
			output_p2pkh.value = decimal("0.0499");

			warden::prepared_transaction prepared;
			prepared.requires_input(algorithm::composition::type::secp256k1, wallet.public_key, (uint8_t*)input_p2pkh_hash.data(), input_p2pkh_hash.size(), std::move(input_p2pkh));
			prepared.requires_input(algorithm::composition::type::secp256k1, wallet.public_key, (uint8_t*)input_p2sh_hash.data(), input_p2sh_hash.size(), std::move(input_p2sh));
			prepared.requires_input(algorithm::composition::type::secp256k1, wallet.public_key, (uint8_t*)input_p2wpkh_hash_1.data(), input_p2wpkh_hash_1.size(), std::move(input_p2wpkh_1));
			prepared.requires_input(algorithm::composition::type::schnorr_taproot, input_p2tr_public_key.data, (uint8_t*)input_p2tr_hash.data(), input_p2tr_hash.size(), std::move(input_p2tr));
			prepared.requires_input(algorithm::composition::type::secp256k1, wallet.public_key, (uint8_t*)input_p2wpkh_hash_2.data(), input_p2wpkh_hash_2.size(), std::move(input_p2wpkh_2));
			prepared.requires_input(algorithm::composition::type::secp256k1, wallet.public_key, (uint8_t*)input_p2wsh_hash.data(), input_p2wsh_hash.size(), std::move(input_p2wsh));
			prepared.requires_input(algorithm::composition::type::secp256k1, wallet.public_key, (uint8_t*)input_p2pk_hash.data(), input_p2pk_hash.size(), std::move(input_p2pk));
			prepared.requires_output(std::move(output_p2wpkh));
			prepared.requires_output(std::move(output_p2pkh));
			validate_transaction(asset, wallet, prepared, "p2pk, p2pkh, p2sh, p2wpkh, p2wsh, p2tr", "010000000001074098b2156e619d1d3b97f59f01c20db9251bda1f8efba3091ffea1c9bf402938010000006b483045022100924d5d4b9b6affaa94e148c2a388f1c5178d99de0c279453166048f87d59277802200a083713e44e248886f0b3bc0f18047ee2c93fa583e02e926ef23decf56a13e7012102986445ccfd323143f392b66b8cfc056df90ebdc110573e3395ee670d5043f23affffffffa0020807878c29d5e524b7945bf5c282cf3efe20022f7d512138a7038e1f7c3d000000001716001418e254169de2c06bbe881f971b312084bf7d7e1cffffffff2997b935e0aff537a6c79d3b40da434daafbfa49534e430fff9b178942c094550000000000ffffffff25b37f14116609bf0334aa538bda9b0edd8fec92afcfdd8816f5c03570cb8f980000000000ffffffff301504e100c831f91f6765908084b2f5d1d979d489dec196f8486fa4a6677a9b0000000000ffffffff25600c74088b1b3d12d8e106b917a69630c82501e2422c36041f24209d94c7cc0100000000ffffffff2ff68c1d9ecbbd544e90827282fc60d2080041610338f27d6778d56c38d2b0f00000000049483045022100b53f92e4b88d431f667e8d347a816775f49bf72edb87999a16846acabe2901f8022048638bfb71b4345effe229328f24474c6897e22133faf3955ed3d54efb76571b01ffffffff0240d2df03000000001600142fe07053c38596c34f561a2565b752272c90e66430244c00000000001976a91418e254169de2c06bbe881f971b312084bf7d7e1c88ac000247304402200134af8e5f1a3d4cf8122b13249bf51bb5b145aedf5ecbdb7ab3b6f643713ec402201ad88b14aa9fbe351e1cec37e6a1e82a10ca3bdd7eecb4e4af151fa09c14457d012102986445ccfd323143f392b66b8cfc056df90ebdc110573e3395ee670d5043f23a024830450221009e81fa743394356ed766c054f35866a9c11629a9280a59d62fff7f76455f85e7022031cf29d8aa011ab13ae8e26871b6719ffd3d6debb9a4b9007ae6007419992223012102986445ccfd323143f392b66b8cfc056df90ebdc110573e3395ee670d5043f23a01404280cfac7cd4491bbd57f5df12bfaad7dbee502575283d143b2cdbb0d6f512fd1673fc20e38498d0eb6be464f755c5cc23ae73f982ec363927a955272fb6bce702483045022100edbc1dd07256ccc930c27f71f7c10aa3838568bd81169d025a82ac1de434e54602201f2b94bef0a15a16c925a50a6783bf4017fb7e518230222faf9287258ea95401012102986445ccfd323143f392b66b8cfc056df90ebdc110573e3395ee670d5043f23a0347304402206942caa371e2d0c7f6b4d3c450710a1a32d9a290870d8650d7b062d481609497022027b2963e282eade76a14f9613b8595623efbc2e54dec62cb4bf3eed5048426cc012102986445ccfd323143f392b66b8cfc056df90ebdc110573e3395ee670d5043f23a1976a91418e254169de2c06bbe881f971b312084bf7d7e1c88ac0000000000");
		});
		use_clean_state([&]()
		{
			auto asset = algorithm::asset::id_of("BCH");
			auto wallet = create_wallet(asset);

			auto input_p2pkh_hash = codec::hex_decode("0x06da9b13756115c79c0361a083d340c75ced09ddfec9a530601d73a0021ba6a5");
			warden::coin_utxo input_p2pkh;
			input_p2pkh.link = warden::wallet_link(user.public_key_hash, wallet.encoded_public_key, wallet.encoded_addresses[1]);
			input_p2pkh.transaction_id = "8d4157a810c52d392c871867fcb5e5375df7102857eea5d770781737c67e5ed4";
			input_p2pkh.index = 0;
			input_p2pkh.value = 0.1;

			warden::coin_utxo output_p2pkh;
			output_p2pkh.link = warden::wallet_link::from_address("bchreg:qzpz97kqvz9jj6tdr6wxdt7zyh7vtm8nwyy4ajnft4");
			output_p2pkh.index = 0;
			output_p2pkh.value = decimal("0.099");

			warden::prepared_transaction prepared;
			prepared.requires_input(algorithm::composition::type::secp256k1, wallet.public_key, (uint8_t*)input_p2pkh_hash.data(), input_p2pkh_hash.size(), std::move(input_p2pkh));
			prepared.requires_output(std::move(output_p2pkh));
			validate_transaction(asset, wallet, prepared, "p2pkh", "0100000001d45e7ec637177870d7a5ee572810f75d37e5b5fc6718872c392dc510a857418d000000006a47304402201200e6ebcf63612f7fd29c5268d5086525d8705248f1f107f861842e35ad88c802207713c74b6649c40be293f9dd23ef1eb338472f4945eda086c75ee501d58cb275412102986445ccfd323143f392b66b8cfc056df90ebdc110573e3395ee670d5043f23affffffff01e00f9700000000001976a9148222fac0608b29696d1e9c66afc225fcc5ecf37188ac00000000");
		});
		use_clean_state([&]()
		{
			auto asset = algorithm::asset::id_of("ETH");
			auto wallet = create_wallet(asset);

			auto signable_link = warden::wallet_link(user.public_key_hash, wallet.encoded_public_key, wallet.encoded_addresses.begin()->second);
			auto signable_message = codec::hex_decode("0x57d10c32396f3368c294f5987ff147ee4ffe3beae206678395b9531a188754fb");
			warden::prepared_transaction prepared;
			prepared.requires_account_input(algorithm::composition::type::secp256k1, std::move(signable_link), wallet.public_key, (uint8_t*)signable_message.data(), signable_message.size(), { { asset, decimal("0.010021") } });
			prepared.requires_account_output("0x92F9727Da59BE92F945a72F6eD9b5De8783e09D3", { { asset, 0.01 } });
			prepared.requires_abi(format::variable(true));
			prepared.requires_abi(format::variable(string()));
			prepared.requires_abi(format::variable(decimal("1000000000000000000")));
			prepared.requires_abi(format::variable((uint32_t)2));
			prepared.requires_abi(format::variable((uint32_t)46860));
			prepared.requires_abi(format::variable((uint32_t)0));
			prepared.requires_abi(format::variable((uint32_t)1000000000));
			prepared.requires_abi(format::variable((uint32_t)21000));
			validate_transaction(asset, wallet, prepared, "eip155, transfer", "0xf86d02843b9aca008252089492f9727da59be92f945a72f6ed9b5de8783e09d3872386f26fc100008083016e3ba05089074862078076438eca98659d4f59e708895e09bc045d7f3f1769aaa8ebb9a05f4cd64e816f541cfbfd38007e409dcb6d7e018f7ee3a759398a9358ec677ff2");

			auto token_asset = algorithm::asset::id_of("ETH", "TT", "0xDcbcBF00604Bad29E53C60ac1151866Fa0CC2920");
			signable_link = warden::wallet_link(user.public_key_hash, wallet.encoded_public_key, wallet.encoded_addresses.begin()->second);
			signable_message = codec::hex_decode("0x430483f3812b96bfe179cd21fb18580c5ba0919c1e25090d9fd740bb238d7bdf");
			prepared = warden::prepared_transaction();
			prepared.requires_account_input(algorithm::composition::type::secp256k1, std::move(signable_link), wallet.public_key, (uint8_t*)signable_message.data(), signable_message.size(), { { asset, decimal("0.000050758") }, { token_asset, decimal("503") } });
			prepared.requires_account_output("0xBA119F26A40145b463DFcae2590b68A057E81d3D", { { token_asset, decimal("503") } });
			prepared.requires_abi(format::variable(true));
			prepared.requires_abi(format::variable(string("0xDcbcBF00604Bad29E53C60ac1151866Fa0CC2920")));
			prepared.requires_abi(format::variable(decimal("1000000000000000000")));
			prepared.requires_abi(format::variable((uint32_t)1));
			prepared.requires_abi(format::variable((uint32_t)46860));
			prepared.requires_abi(format::variable((uint32_t)0));
			prepared.requires_abi(format::variable((uint32_t)1000000000));
			prepared.requires_abi(format::variable((uint32_t)50758));
			validate_transaction(asset, wallet, prepared, "eip155, erc20 transfer", "0xf8ab01843b9aca0082c64694dcbcbf00604bad29e53c60ac1151866fa0cc292080b844a9059cbb000000000000000000000000ba119f26a40145b463dfcae2590b68a057e81d3d00000000000000000000000000000000000000000000001b4486fafde57c000083016e3ba0183cd5044b62f80fa3bb2ffcffb0d5eac450c8275cd1d2b3bb77897c932aee80a0384e8bf3e1b50f62f1db7e431783f30831849aa649bf2a602ae0103740934fea");

			signable_link = warden::wallet_link(user.public_key_hash, wallet.encoded_public_key, wallet.encoded_addresses.begin()->second);
			signable_message = codec::hex_decode("0xee37560b1bf4ec6cb472518d81d71a485e99f01ceaff9bedcd94567711193c5b");
			prepared = warden::prepared_transaction();
			prepared.requires_account_input(algorithm::composition::type::secp256k1, std::move(signable_link), wallet.public_key, (uint8_t*)signable_message.data(), signable_message.size(), { { asset, decimal("0.100021") } });
			prepared.requires_account_output("0x92F9727Da59BE92F945a72F6eD9b5De8783e09D3", { { asset, 0.1 } });
			prepared.requires_abi(format::variable(false));
			prepared.requires_abi(format::variable(string()));
			prepared.requires_abi(format::variable(decimal("1000000000000000000")));
			prepared.requires_abi(format::variable((uint32_t)2));
			prepared.requires_abi(format::variable((uint32_t)46860));
			prepared.requires_abi(format::variable((uint32_t)0));
			prepared.requires_abi(format::variable((uint32_t)1000000000));
			prepared.requires_abi(format::variable((uint32_t)21000));
			validate_transaction(asset, wallet, prepared, "eip1559, transfer", "0x02f87082b70c0280843b9aca008252089492f9727da59be92f945a72f6ed9b5de8783e09d388016345785d8a000080c001a08b651c3de6d63307b0b9cfc1b227abea5843f16363cebdba174a40165421f231a0550575cda0195e4f1e64d4d6e3f49551e894356546716b17278401dd0c23a376");

			signable_link = warden::wallet_link(user.public_key_hash, wallet.encoded_public_key, wallet.encoded_addresses.begin()->second);
			signable_message = codec::hex_decode("0x2785859c7efc21a7f372d723ff833101a8ec5f37003b698fd5afa0e54dec93f4");
			prepared = warden::prepared_transaction();
			prepared.requires_account_input(algorithm::composition::type::secp256k1, std::move(signable_link), wallet.public_key, (uint8_t*)signable_message.data(), signable_message.size(), { { asset, decimal("0.000050758") }, { token_asset, decimal("503") } });
			prepared.requires_account_output("0xBA119F26A40145b463DFcae2590b68A057E81d3D", { { token_asset, decimal("503") } });
			prepared.requires_abi(format::variable(false));
			prepared.requires_abi(format::variable(string("0xDcbcBF00604Bad29E53C60ac1151866Fa0CC2920")));
			prepared.requires_abi(format::variable(decimal("1000000000000000000")));
			prepared.requires_abi(format::variable((uint32_t)2));
			prepared.requires_abi(format::variable((uint32_t)46860));
			prepared.requires_abi(format::variable((uint32_t)0));
			prepared.requires_abi(format::variable((uint32_t)1000000000));
			prepared.requires_abi(format::variable((uint32_t)50758));
			validate_transaction(asset, wallet, prepared, "eip1559, erc20 transfer", "0x02f8ad82b70c0280843b9aca0082c64694dcbcbf00604bad29e53c60ac1151866fa0cc292080b844a9059cbb000000000000000000000000ba119f26a40145b463dfcae2590b68a057e81d3d00000000000000000000000000000000000000000000001b4486fafde57c0000c001a0367dabd1749f8ce1fcf59096487f0a3d591918f29d88d9e59c539a63b6c107d2a04a3276c7b13174647fc0cb81a465de2e089d46b77a6102b35177585907b6180d");
		});
		use_clean_state([&]()
		{
			auto asset = algorithm::asset::id_of("XRP");
			auto wallet = create_wallet(asset);

			auto signable_link = warden::wallet_link(user.public_key_hash, wallet.encoded_public_key, wallet.encoded_addresses.begin()->second);
			auto signable_message = codec::hex_decode("0x53545800120000220000000024006115562e00000000201b006117fb614000000002b709b068400000000000000c7321ed2a994a958414a9dac047fd32001847954f89f464433cb04266fde37d6aff15448114c7f083a28227b588c13becf3f353e06d2e4f2fee8314f667b0ca50cc7709a220b0561b85e53a48461fa8");
			warden::prepared_transaction prepared;
			prepared.requires_account_input(algorithm::composition::type::ed25519, std::move(signable_link), wallet.public_key, (uint8_t*)signable_message.data(), signable_message.size(), { { asset, decimal("45.550012") } });
			prepared.requires_account_output("rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe", { { asset, decimal("45.55") } });
			prepared.requires_abi(format::variable(string()));
			prepared.requires_abi(format::variable((uint32_t)6362454));
			prepared.requires_abi(format::variable((uint32_t)6363131));
			prepared.requires_abi(format::variable((uint32_t)12));
			validate_transaction(asset, wallet, prepared, "payment", "120000220000000024006115562E00000000201B006117FB614000000002B709B068400000000000000C7321ED2A994A958414A9DAC047FD32001847954F89F464433CB04266FDE37D6AFF15447440B32F9A9259C13C84AECFE587730DA2F61F0546478BEAA3B8E38EF859217A2F37A729E33FFD8F2505746F9A38AE9E0EA5280996C6D62113EFA06F9AAA0139D5088114C7F083A28227B588C13BECF3F353E06D2E4F2FEE8314F667B0CA50CC7709A220B0561B85E53A48461FA8");
		});
		use_clean_state([&]()
		{
			auto asset = algorithm::asset::id_of("XLM");
			auto wallet = create_wallet(asset);

			auto signable_link = warden::wallet_link(user.public_key_hash, wallet.encoded_public_key, wallet.encoded_addresses.begin()->second);
			auto signable_message = codec::hex_decode("0x1a6e7daa8fbd8aab869ebeafc8650d911a948d6e8166aec4fcec5490e359f81d");
			warden::prepared_transaction prepared;
			prepared.requires_account_input(algorithm::composition::type::ed25519, std::move(signable_link), wallet.public_key, (uint8_t*)signable_message.data(), signable_message.size(), { { asset, decimal("2200.00001") } });
			prepared.requires_account_output("GAIH3ULLFQ4DGSECF2AR555KZ4KNDGEKN4AFI4SU2M7B43MGK3QJZNSR", { { asset, decimal("2200") } });
			prepared.requires_abi(format::variable((uint64_t)1561327986278402));
			prepared.requires_abi(format::variable((uint32_t)0));
			prepared.requires_abi(format::variable((uint32_t)1));
			prepared.requires_abi(format::variable(false));
			prepared.requires_abi(format::variable(string()));
			prepared.requires_abi(format::variable(string()));
			prepared.requires_abi(format::variable((uint32_t)0));
			validate_transaction(asset, wallet, prepared, "payment", "AAAAACqZSpWEFKnawEf9MgAYR5VPifRkQzywQmb9431q/xVEAAAAZAAFjAUAAAACAAAAAAAAAAAAAAABAAAAAAAAAAEAAAAAEH3Rayw4M0iCLoEe96rPFNGYim8AVHJU0z4ebYZW4JwAAAAAAAAABR9NXAAAAAAAAAAAAWr/FUQAAABAIpGae7c2mwFnhzxojX7ZixCelXJWbBBj55IlADoZ70ngTLBXk80yMUTLNvDA4PepBbDDoFo+pbVlupKIRGqkCQ==");

			signable_link = warden::wallet_link(user.public_key_hash, wallet.encoded_public_key, wallet.encoded_addresses.begin()->second);
			signable_message = codec::hex_decode("0xc23a0791a11ebefd653684792b4001e294440ce67979fb7a0dc2915ca4818e22");
			prepared = warden::prepared_transaction();
			prepared.requires_account_input(algorithm::composition::type::ed25519, std::move(signable_link), wallet.public_key, (uint8_t*)signable_message.data(), signable_message.size(), { { asset, decimal("100.00001") } });
			prepared.requires_account_output("GD4QDZNYKL4VH7QGVP47DZZBEUB5KR53SI2RACPDNTHCOSAQJTN3RW2Z", { { asset, decimal("100") } });
			prepared.requires_abi(format::variable((uint64_t)1561327986278403));
			prepared.requires_abi(format::variable((uint32_t)1));
			prepared.requires_abi(format::variable((uint32_t)0));
			prepared.requires_abi(format::variable(true));
			prepared.requires_abi(format::variable(string()));
			prepared.requires_abi(format::variable(string()));
			prepared.requires_abi(format::variable((uint32_t)0));
			validate_transaction(asset, wallet, prepared, "create_account", "AAAAACqZSpWEFKnawEf9MgAYR5VPifRkQzywQmb9431q/xVEAAAAZAAFjAUAAAADAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAA+QHluFL5U/4Gq/nx5yElA9VHu5I1EAnjbM4nSBBM27gAAAAAO5rKAAAAAAAAAAABav8VRAAAAEBzMjoGQoY19x/7xSfKDYuot6qhkxGIur4K5FVyW0S5alro19p8abVYit9sqbYO3HsPKjtd8Qsfeu63qxU/adoP");
		});
		use_clean_state([&]()
		{
			auto asset = algorithm::asset::id_of("SOL");
			auto wallet = create_wallet(asset);

			auto signable_link = warden::wallet_link(user.public_key_hash, wallet.encoded_public_key, wallet.encoded_addresses.begin()->second);
			auto signable_message = codec::hex_decode("0x80010001032a994a958414a9dac047fd32001847954f89f464433cb04266fde37d6aff15440963cbfdea28293c02cd965c46e7a6f26bc5f26da4fa00dda8c8ade49f96dcad0000000000000000000000000000000000000000000000000000000000000000b83691e4405ab95ed6264b5942eb150deb64c9d0688940be0f6548da25de783c01020200010c02000000807a77230100000000");
			warden::prepared_transaction prepared;
			prepared.requires_account_input(algorithm::composition::type::ed25519, std::move(signable_link), wallet.public_key, (uint8_t*)signable_message.data(), signable_message.size(), { { asset, decimal("4.890005") } });
			prepared.requires_account_output("devwuNsNYACyiEYxRNqMNseBpNnGfnd4ZwNHL7sphqv", { { asset, decimal("4.89") } });
			prepared.requires_abi(format::variable((uint64_t)1000000000));
			prepared.requires_abi(format::variable(string()));
			prepared.requires_abi(format::variable(string()));
			prepared.requires_abi(format::variable(string()));
			prepared.requires_abi(format::variable(string("DQ6H97iaf92qFZAWFSu57x74i47L4MJL5vjfun8pMrCj")));
			validate_transaction(asset, wallet, prepared, "transfer", "2WdkL4bmuDPUcfPRuL8r5XxJi3CkA6d2rzVe8voUUduLDvrAqNMDrtQHtVvoMxd9XiV5utj1KiJxQWRxwPcur1GULgPy25pWqKFTqqJ8XYA4Wsutq2VzGo3YBUecKC9HYtQnmMiufpQeYChj91geaimZPvhaBgvVF58bHKchWHJiuywGNq8PHhsaDemprtxk12uyswZBmMiSLifE6EATx8bjXgXTbMWyytYM2Xz6u7Hh1D6Jna5D2uKSuVBF2nQuzuspgGyk4qWVfCUP5CNhBn5B6sjGFeEuF575GAQo");

			auto token_asset = algorithm::asset::id_of("SOL", "9YaGkvrR1fjXSAm7LTcQYXZiZfub2EuWvVxBmRSHcwHZ", "9YaGkvrR1fjXSAm7LTcQYXZiZfub2EuWvVxBmRSHcwHZ");
			signable_link = warden::wallet_link(user.public_key_hash, wallet.encoded_public_key, wallet.encoded_addresses.begin()->second);
			signable_message = codec::hex_decode("0x80010001042a994a958414a9dac047fd32001847954f89f464433cb04266fde37d6aff1544437b32d02edb961d6ffba969407c441a127befb1fe6885fa40f3d9e1dd7f9306d36dc35d5d43cb85d730bbf57899cb2266076f149fdf00b5491b69d1ad764df306ddf6e1d765a193d9cbe146ceeb79ac1cb485ed5f5b37913a8cf5857eff00a95abee248b8b08441f683b2e58d6b7c62bfa977bb775f0ef37facee593d0b1269010303010200090350a505000000000000");
			prepared = warden::prepared_transaction();
			prepared.requires_account_input(algorithm::composition::type::ed25519, std::move(signable_link), wallet.public_key, (uint8_t*)signable_message.data(), signable_message.size(), { { asset, decimal("0.000015") }, { token_asset, decimal("3700") } });
			prepared.requires_account_output("4Bs1nFL71Yaq2HJ3pSk3WHdbhkWeqnrLYQZDhqjDfb53", { { token_asset, decimal("3700") } });
			prepared.requires_abi(format::variable((uint64_t)100));
			prepared.requires_abi(format::variable(string("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")));
			prepared.requires_abi(format::variable(string("5YRGqmfQGcAii8szURA3ZztXfpre1ZnajJcS63GJi4yK")));
			prepared.requires_abi(format::variable(string("FEL6m5CE2P3JTW1ceo48VerTUSWDte6eXzgrcmcftvyQ")));
			prepared.requires_abi(format::variable(string("77EWfi8yvGJNRsC9BRHepMtBJ2RDEDAkZNWAT4YJNMYU")));
			validate_transaction(asset, wallet, prepared, "spl transfer", "2M37Gqx1LExUQhQzf3vRt13knPtPMsinbC4CeqVtT11tnSdLfiSF3LzxFBqhHbxMo9BdsYWvgze55in6r1ftZ4QybfsEATV5QDNKuuYPb5TuE6KtYEaw4MaGg6fhSG1XA5K8z5ttS7pjzdzd1k53u6LTApRTCFCKnuUB6i5u9nbsH5NwJeCxRd2PqjyZgsrpkHBxVwiwfP6QEgadqC9rGcGWH75Ep37yrQ1A6Mt63DAkGdqRAKgqc8utxPBuivJff39Kt9CNGvpgixj4HhekaqVKppPPhAicvqLgYSms4QjqJbkDe3dujUZwk8ii2FCwoY53JtBk9paycbpYX");
		});
		use_clean_state([&]()
		{
			auto asset = algorithm::asset::id_of("ADA");
			auto wallet = create_wallet(asset);

			auto input_hash = codec::hex_decode("0x14b33fbdd10c0931057b2c66e56b08cf01523480769153e3433050c571dc23e6");
			warden::coin_utxo input;
			input.link = warden::wallet_link(user.public_key_hash, wallet.encoded_public_key, wallet.encoded_addresses[1]);
			input.transaction_id = "f887787271fa3538f574bb0a95f1178377dd70a98813657764241fdf4e0ca7b7";
			input.index = 1;
			input.value = decimal("9965.667678");

			warden::coin_utxo output_1;
			output_1.link = warden::wallet_link::from_address("addr_test1vqeux7xwusdju9dvsj8h7mca9aup2k439kfmwy773xxc2hcu7zy99");
			output_1.index = 0;
			output_1.value = decimal("2100");

			warden::coin_utxo output_2;
			output_2.link = input.link;
			output_2.index = 1;
			output_2.value = decimal("7865.501517");

			warden::prepared_transaction prepared;
			prepared.requires_input(algorithm::composition::type::ed25519, wallet.public_key, (uint8_t*)input_hash.data(), input_hash.size(), std::move(input));
			prepared.requires_output(std::move(output_1));
			prepared.requires_output(std::move(output_2));
			prepared.requires_abi(format::variable((uint64_t)166161));
			validate_transaction(asset, wallet, prepared, "p2pkh", "84a30081825820f887787271fa3538f574bb0a95f1178377dd70a98813657764241fdf4e0ca7b7010182a200581d6033c378cee41b2e15ac848f7f6f1d2f78155ab12d93b713de898d855f011a7d2b7500a200581d6042a00dfc0e9577dd74673d4b90b1e4a00e8a7fe0778dd134d268a95f011b00000001d4d2074d021a00028911a100818258202a994a958414a9dac047fd32001847954f89f464433cb04266fde37d6aff15445840c206b6818268d7a95348ac7f609353f39f33388317c8888bc6b3389edadbeed4b5e3bdea395ba71f80a0db2e0dbecf19ecff7346c08b11b9c980faec2e64110df5f6");

			auto token_contract = "bd976e131cfc3956b806967b06530e48c20ed5498b46a5eb836b61c2";
			auto token_symbol = "tMILKv2";
			input_hash = codec::hex_decode("0x66bb498dd4f2840ef018b8392c58fd198f334474b5c9b96d7412b1b4cee39b0b");
			input = warden::coin_utxo();
			input.link = warden::wallet_link(user.public_key_hash, wallet.encoded_public_key, wallet.encoded_addresses[1]);
			input.transaction_id = "0f7cad6020aaf0c462cfb6cba2b5f4102910b7bf7101ed609eb887188b19ad6f";
			input.index = 1;
			input.value = decimal("9940.752346");
			input.apply_token_value(token_contract, token_symbol, decimal("999995689"), 0);

			output_1 = warden::coin_utxo();
			output_1.link = warden::wallet_link::from_address("addr_test1vzpkkthr9azvuagxcf0m27qvzdad7n95jutgcdtglgmhdns998vsz");
			output_1.index = 0;
			output_1.value = decimal("1.655136");
			output_1.apply_token_value(token_contract, token_symbol, decimal("65483"), 0);

			output_2 = warden::coin_utxo();
			output_2.link = input.link;
			output_2.index = 1;
			output_2.value = decimal("9938.927089");
			output_2.apply_token_value(token_contract, token_symbol, decimal("999930206"), 0);

			prepared = warden::prepared_transaction();
			prepared.requires_input(algorithm::composition::type::ed25519, wallet.public_key, (uint8_t*)input_hash.data(), input_hash.size(), std::move(input));
			prepared.requires_output(std::move(output_1));
			prepared.requires_output(std::move(output_2));
			prepared.requires_abi(format::variable((uint64_t)170121));
			validate_transaction(asset, wallet, prepared, "p2pkh asset", "84a300818258200f7cad6020aaf0c462cfb6cba2b5f4102910b7bf7101ed609eb887188b19ad6f010182a200581d60836b2ee32f44ce7506c25fb5780c137adf4cb497168c3568fa3776ce01821a00194160a1581cbd976e131cfc3956b806967b06530e48c20ed5498b46a5eb836b61c2a147744d494c4b763219ffcba200581d6042a00dfc0e9577dd74673d4b90b1e4a00e8a7fe0778dd134d268a95f01821b000000025067fdf1a1581cbd976e131cfc3956b806967b06530e48c20ed5498b46a5eb836b61c2a147744d494c4b76321a3b99b95e021a00029889a100818258202a994a958414a9dac047fd32001847954f89f464433cb04266fde37d6aff1544584073ab56c71d34ab1c2c5b2558ca6a31eabbd5c240e0424692e82f737d0e0cf0d436c7a023e90d4ffc4c1fe78ffff064ff61fc4ac97ecddc5032138e5f33dffe0bf5f6");
		});
		use_clean_state([&]()
		{
			auto asset = algorithm::asset::id_of("TRX");
			auto wallet = create_wallet(asset);

			auto signable_link = warden::wallet_link(user.public_key_hash, wallet.encoded_public_key, wallet.encoded_addresses.begin()->second);
			auto signable_message = codec::hex_decode("0x6c30ab9d12ae48c5c6800533451ef201dcc807980ea18739301ac48c2ddef3ce");
			warden::prepared_transaction prepared;
			prepared.requires_account_input(algorithm::composition::type::secp256k1, std::move(signable_link), wallet.public_key, (uint8_t*)signable_message.data(), signable_message.size(), { { asset, decimal("22.4") } });
			prepared.requires_account_output("TXNE2M4GSw6tjVsGeux9nbVEhihGU6hBeV", { { asset, 14 } });
			prepared.requires_abi(format::variable(string()));
			prepared.requires_abi(format::variable("091a"));
			prepared.requires_abi(format::variable("844ba957b61a108b"));
			prepared.requires_abi(format::variable((uint64_t)1744587342000));
			prepared.requires_abi(format::variable((uint64_t)1744587282000));
			prepared.requires_abi(format::variable((uint32_t)1000000));
			validate_transaction(asset, wallet, prepared, "transfer", "78da8d52cb6edc300cfc179d8394d45b7b6d2fbdf716040645518951ef7a617bf340907f2fddb441da5e6a5fe499213923f3c53c8ceb582731874ed32a57667bfafac51c4c6407544b434be233078e192038e7034ab7808d39432a19843027571c20b10a6d6bd21d8bb9320b3d0e8d361aeee5493b02818582642de4ec7da512528d4808b97aa8903197cce29c0da4c33220dae8816c4b3e950431588929767d53e418222a569253d429d66c4f906cecc9ebd78eb095e015c128c9c51843b27ec725bda12e79b44e6362f0c89a859bdaebad80b0f6e08205b1359fa44a0b2dd6184b40bbab856a80ae508d6a90a2ce911442e5802d17aeaac612b3c79ca1aa0e628206c439bc252c0098811c3b9f3edc9439bc189e4fdb42bc99c3cd8b39d34247d964d999079a2eb21fb679a0d6165957bdd6ff37a383e6c7932c7f14ff6f6e2da6e37c39a92ff4f0f379d565793ecb7059266db51fafefe6f96e123a8feb35cfc74fe765de669ea7eb6f0b9dd62ecbe7dfe17ed56addbfd4ad5e88f4a14e337f1feaf326bbd37d73cc47e29ed67bc5ffde24d5c8d3795c681be7937a4dde07dd4f6fd5b0ce1c8fb26e743cbf3336bf315d6498c6e3b8e70bf01e701def4eb45d16757a635216140ee21d736dcd49c206d956a2ee7b0fb6d8dea9462aa2bfda7696dd54b40553f5badf043166110fa52226ac56d791946c4cb53aa9547bd8fb46c756c99e9daa5ae642b178b2b9219bdbd71fabe0141d");

			auto token_asset = algorithm::asset::id_of("TRX", "GFC", "TUiyUe3uqtiT8cFkfhW6Q28Z99sY7o82Xr");
			signable_link = warden::wallet_link(user.public_key_hash, wallet.encoded_public_key, wallet.encoded_addresses.begin()->second);
			signable_message = codec::hex_decode("0xc7654e7252c5133d358940cbffff610443358dc18c0411225d7d2596952dfc07");
			prepared = warden::prepared_transaction();
			prepared.requires_account_input(algorithm::composition::type::secp256k1, std::move(signable_link), wallet.public_key, (uint8_t*)signable_message.data(), signable_message.size(), { { asset, decimal("14.0228") }, { token_asset, decimal("8") } });
			prepared.requires_account_output("TXNE2M4GSw6tjVsGeux9nbVEhihGU6hBeV", { { token_asset, decimal("8") } });
			prepared.requires_abi(format::variable("TUiyUe3uqtiT8cFkfhW6Q28Z99sY7o82Xr"));
			prepared.requires_abi(format::variable("08ca"));
			prepared.requires_abi(format::variable("9dd563feb883a59e"));
			prepared.requires_abi(format::variable((uint64_t)1744587102000));
			prepared.requires_abi(format::variable((uint64_t)1744587042000));
			prepared.requires_abi(format::variable((uint64_t)1000000));
			validate_transaction(asset, wallet, prepared, "trc20 transfer", "78dacd534d6fdb300cfd2f3a171d497de7ba5d76de6e45115012951a73e2c076fa81a2ff7dccda0eddb001c54ea301437ae493f848f1d1dc0ecb5046319bcee3221766bdfffcc96c4c8dc13b89e4a97ab4b6599fb2835aba5a4070ce2ad22aa60a0e91c8b7d8c8e7903db55e219a0b33f3ddb6f1cadb1bb9d7138181205526fde7d67cb05d4a4a967d160705583aa722d69267164048d89138eb8a2d46177384e049420c5dbf186af00115cbd12a6a156bd423440a3d3add9d914ae29d2259e35591eab1a1298ba22a50bfc4b317838d0e150346efb0c69c6acbc8bd6590aa67d58c19b13517a548f32d94a04a917e44b7925d684c48d25d512c5adda41638f92e2e751b08ac1039a76a7caea5c05fcca170f1d0f582128089b50951a2f745bbd09252f56ecc01fed92223e91f1ab4dcc373bd3300262d72b5ee6ddfcce6d1d4e9b0ce5c57b3b97a34479e792fabcc67cf2d8f27392f9e43cdff224d054c770799b7dcda2ccba2a9bdbfa34a7e55fc2bff9d3d364f3a400f47d99ee65189e7e5e56e9a76a3f071582eebb4ff709ca775aad378f9751e763b99bfec795e3fbe96f985afdc3fbbafb53dd2b7659ceab76d7958e59cdf79aacc5bc70d2f378aff3e651a23f7c761e675980e66a333e57c8aa86309a0f70e7b5956de1f7f7ac03d7bbac8761cf683be02f42fc5d644976177e0f5346bb6572695486a88422e5bb190a809730cd942a65a142461742d914d981c154bd003d750ba2db9c7ecd89656a566b02eb7e8bb3e4c02a542b6b569404a4e4b8d22ad047694b224db3df71c5a2d58cdf5d377ea795376");
		});
	}
	/* blockchain containing all transaction types (zero balance accounts, valid regtest chain) */
	static void blockchain_full_coverage(vector<account>* userdata)
	{
		use_clean_state([&]()
		{
			uptr<schema> data = userdata ? nullptr : var::set::array();
			vector<account> users =
			{
				account(ledger::wallet::from_seed("000001"), 0),
				account(ledger::wallet::from_seed("000000"), 0),
				account(ledger::wallet::from_seed("000002"), 0)
			};
			TEST_BLOCK(&generators::validator_registration_full, "0x455300fb979507333ab6948b6ad65f9864424f9fd7d485ca908d4e74675dc0b6", 1);
			TEST_BLOCK(std::bind(&generators::validator_enable_validator, std::placeholders::_1, std::placeholders::_2, 2), "0x5859c9178dca229ce29899eb106bfbb140cddc2854a59337d8c9a285af2cd866", 2);
			TEST_BLOCK(&generators::depository_registration_full, "0xdb92550c9b9e44aff1fe2a51cf4646933e345969d972a0c9c70dc21bd868830d", 3);
			TEST_BLOCK(&generators::depository_account_registration_full, "0x0cecdbcc61df13d1e31b30417d32a7d0c170884be78fc8febc23e6ee411de345", 4);
			TEST_BLOCK(&generators::depository_transaction_registration_full, "0xcbd22637a94da2acaabd5338fcb5143751ecc5660283da092153c8758a5b222f", 6);
			TEST_BLOCK(&generators::account_transfer_stage_1, "0x5a026823416520bf8596ed0886976000e82d5a8ea8a1d287285be7a1d72d5b86", 7);
			TEST_BLOCK(&generators::account_transfer_stage_2, "0x455043564667a3d7a234bbbd6c1c08711ed4b0c9cfa25dfd575ea7236f82de33", 8);
			TEST_BLOCK(std::bind(&generators::account_transfer_to_account, std::placeholders::_1, std::placeholders::_2, 0, algorithm::asset::id_of("BTC"), users[2].wallet.get_address(), 0.05), "0x5bcd3a13492010c76930adf30d36a83547e9e04d2747979f73e414d92e65df6c", 9);
			TEST_BLOCK(&generators::account_transaction_rollup, "0x0b07dcea12550ff433deafda4579542df39e616294578874fd9d241f672e8621", 10);
			TEST_BLOCK(&generators::account_program_deployment, "0x7f08aabe930803ba6e6d051174f1e85576444d52cf4b5d06441fe208d0ae94c9", 11);
			TEST_BLOCK(&generators::account_program_invocation, "0x330fa22fd5d9b55846d4286cea6521b1df883f0dbeee1e2ded5814b4c2220f43", 12);
			TEST_BLOCK(&generators::depository_regrouping, "0x51e19f91477f9b39b2689b46c5cdb7496f3850eaf9752dc5ac81fda9428cf6ca", 13);
			TEST_BLOCK(&generators::depository_withdrawal_stage_1, "0xe933e285533d38a936adc0cad0b9cb77c95ec5cace534733737f0ab5c53e4d8f", 17);
			TEST_BLOCK(&generators::depository_withdrawal_stage_2, "0x1451c17019ae682916d07bdfed39947a3e3c4a8e6d1e179e15fc97ffc1e39f44", 19);
			TEST_BLOCK(&generators::depository_withdrawal_stage_3, "0x117fb17b608bfcaaa5ff19ca008c1aba6a69a162262a0b2ae930441aa1a90d59", 21);
			TEST_BLOCK(std::bind(&generators::validator_disable_validator, std::placeholders::_1, std::placeholders::_2, 2), "0xbe8fdaa51d8c05534ed613cd3afa334cef55338a8d9da82d3de8c4e243efe716", 23);
			if (userdata != nullptr)
				*userdata = std::move(users);
			else
				console::get()->jwrite_line(*data);
		});
	}
	/* blockchain containing some transaction types (non-zero balance accounts, valid regtest chain) */
	static void blockchain_partial_coverage(vector<account>* userdata)
	{
		use_clean_state([&]()
		{
			uptr<schema> data = userdata ? nullptr : var::set::array();
			vector<account> users =
			{
				account(ledger::wallet::from_seed("000000"), 0)
			};
			TEST_BLOCK(&generators::validator_registration_partial, "0xdb92d9af9979338b30c84c659562b682ce991863ed1330e56fab4fcb7a962d16", 1);
			TEST_BLOCK(&generators::depository_registration_partial, "0xee9d3dda7455fb9b70e9653cd045d6ab3bec5f41cb50bda9cc04a4c671fb6c3d", 2);
			TEST_BLOCK(&generators::depository_account_registration_partial, "0x62a407cbf1a4eb74d1d53261d57916d868f851c8858b1c8929d1bee3dc73421a", 3);
			TEST_BLOCK(&generators::depository_transaction_registration_partial, "0x603554d3ea15fe3015a76396938b4728a39b204463c1a3527b4ebdc38e50a913", 5);
			TEST_BLOCK(std::bind(&generators::account_transfer_to_account, std::placeholders::_1, std::placeholders::_2, 0, algorithm::asset::id_of("BTC"), "tcrt1xrwrv9zmn30f965xczdrgupyp62jr0pq3er4ndnk39cpvtzaucjyqyltwmesfhtrvf56rk9", 0.1), "0x69b70e705c51c620cefe0199424660032b69d8415ad31fbced9e390081c1fae6", 6);
			if (userdata != nullptr)
				*userdata = std::move(users);
			else
				console::get()->jwrite_line(*data);
		});
	}
	/* verify current blockchain */
	static void blockchain_verification()
	{
		auto* term = console::get();
		auto chain = storages::chainstate(__func__);
		VI_PANIC(!chain.get_checkpoint_block_number().or_else(0), "blockchain cannot be validated without re-executing entire blockchain");

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

			ledger::block_evaluation evaluation;
			auto validation = next->validate(parent_block.address(), &evaluation);
			if (!validation)
			{
				result->set("status", var::string("block validation test failed"));
				result->set("detail", var::string(validation.error().message()));
				break;
			}

			auto proof = next->as_proof(parent_block.address(), &evaluation.state);
			for (auto& tx : next->transactions)
			{
				if (!proof.has_transaction(tx.receipt.transaction_hash))
				{
					result->set("transaction_hash", var::string(algorithm::encoding::encode_0xhex256(tx.receipt.transaction_hash)));
					result->set("status", var::string("transaction merkle test failed"));
					term->jwrite_line(*data);
					VI_PANIC(false, "block verification failed");
				}
				else if (!proof.has_receipt(tx.receipt.as_hash()))
				{
					result->set("transaction_hash", var::string(algorithm::encoding::encode_0xhex256(tx.receipt.transaction_hash)));
					result->set("status", var::string("receipt merkle test failed"));
					term->jwrite_line(*data);
					VI_PANIC(false, "block verification failed");
				}
			}

			size_t state_index = 0;
			for (auto& state : evaluation.state.at(ledger::work_state::finalized))
			{
				uint256_t hash = state.second->as_hash();
				if (!proof.has_state(hash))
				{
					result->set("state_hash", var::string(algorithm::encoding::encode_0xhex256(hash)));
					result->set("status", var::string("state merkle test failed"));
					term->jwrite_line(*data);
					VI_PANIC(false, "block verification failed");
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
		term->jwrite_line(*data);
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

		auto transaction = transactions::certification();
		transaction.set_asset("BTC");
		transaction.enable_block_production();
		transaction.allocate_attestation_stake(algorithm::asset::id_of("ETH"), decimal::zero());
		transaction.allocate_attestation_stake(algorithm::asset::id_of("XRP"), decimal::zero());
		transaction.allocate_attestation_stake(algorithm::asset::id_of("BTC"), decimal::zero());
		transaction.allocate_participation_stake(algorithm::asset::id_of("ETH"), decimal::zero());
		transaction.allocate_participation_stake(algorithm::asset::id_of("XRP"), decimal::zero());
		transaction.allocate_participation_stake(algorithm::asset::id_of("BTC"), decimal::zero());
		VI_PANIC(transaction.sign(from, 1, decimal::zero()), "certification not signed");

		uptr<schema> data = var::set::object();
		data->set("transaction_gas_limit", algorithm::encoding::serialize_uint256(transaction.gas_limit));
		data->set("block_gas_limit", algorithm::encoding::serialize_uint256(ledger::block::get_gas_limit()));
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
			user.nonce = user.wallet.get_latest_nonce().or_else(0);

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
			priority = environment.priority(user.wallet.public_key_hash, user.wallet.secret_key).or_else(std::numeric_limits<uint64_t>::max());
			if (!priority)
				break;
		}

		VI_PANIC(priority == 0, "block proposal not allowed");
		for (auto& transaction : transactions)
		{
			if (!transaction->is_recoverable())
			{
				if (transaction->gas_price.is_nan())
					transaction->gas_price = decimal::zero();
				for (auto& [attestation_user, attestation_user_nonce] : users)
					VI_PANIC(((ledger::attestation_transaction*)*transaction)->sign(attestation_user.secret_key), "transaction not attested");
				if (!transaction->gas_limit)
					transaction->gas_limit = ledger::transaction_context::calculate_tx_gas(*transaction).or_else(transaction->gas_limit);
			}
		}

		if (!environment.apply(std::move(transactions)))
			VI_PANIC(false, "empty block not allowed");

		string errors;
		auto evaluation = environment.evaluate(&errors);
		if (!errors.empty())
			VI_PANIC(false, "block evaluation error: %s", errors.c_str());

		auto proposal = std::move(evaluation.expect("block evaluation failed"));
		environment.solve(proposal.block).expect("block solution failed");
		if (results != nullptr)
			environment.verify(proposal.block, &proposal.state).expect("block verification failed");

		transactions = vector<uptr<ledger::transaction>>();
		proposal.checkpoint().expect("block checkpoint failed");
		if (results != nullptr)
			results->push(proposal.as_schema().reset());

		vector<ledger::wallet> validators;
		validators.reserve(users.size());
		for (auto& [user, user_nonce] : users)
			validators.push_back(user);

		auto dispatcher = p2p::local_dispatch_context(validators);
		for (auto& [user, user_nonce] : users)
		{
			dispatcher.set_running_validator(user.public_key_hash);
			dispatcher.dispatch_sync(proposal.block);
			if (!dispatcher.outputs.empty())
			{
				user_nonce = user.get_latest_nonce().or_else(0);
				for (auto& transaction : dispatcher.outputs)
				{
					if (transaction->is_recoverable())
						VI_PANIC(transaction->sign(user.secret_key, user_nonce++, decimal::zero()), "dispatch transaction not signed");
				}
				transactions.insert(transactions.end(), std::make_move_iterator(dispatcher.outputs.begin()), std::make_move_iterator(dispatcher.outputs.end()));
				dispatcher.outputs.clear();
			}
			if (!dispatcher.errors.empty())
			{
				for (auto& transaction : dispatcher.errors)
					VI_PANIC(false, "%s", transaction.second.c_str());
				dispatcher.errors.clear();
			}
		}

		dispatcher.checkpoint().expect("dispatcher checkpoint error");
		if (!transactions.empty())
			new_block_from_list(results, users, std::move(transactions));

		return proposal.block;
	}
	template <typename f>
	static void use_clean_state(f&& callback)
	{
		auto& params = protocol::change();
		auto path = params.database.location();
		params.database.reset();
		os::directory::remove(path);

		auto chain = storages::chainstate(__func__);
		chain.clear_indexer_cache();
		callback();
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
		uint32_t index = from_string<uint32_t>(number.substr(0, number.find_first_not_of("0123456789"))).or_else(1);

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
			term->write_color(std_color::white, std_color::dark_green);
			term->fwrite("  CONSENSUS TEST FINISHED  ");
			term->clear_color();
			term->write("\n\n");
			term->read_char();
		}

		return exit_code;
	}
	/* warden node for debugging */
	static int warden(int argc, char* argv[])
	{
		VI_PANIC(argc > 1, "config path argument is required");
		vitex::runtime scope;
		protocol params = protocol(argc, argv);
		params.user.nss.server = true;

		auto* term = console::get();
		term->show();

		auto asset = algorithm::asset::id_of("XMR");
		nss::server_node& synchronization = *nss::server_node::get();
		synchronization.add_node(asset, "http://localhost:18081/", 0);
		synchronization.scan_from_block_height(asset, 1);

		service_control control;
		control.bind(synchronization.get_entrypoint());

		auto test_case = coasync<void>([&]() -> promise<void>
		{
			auto* server = nss::server_node::get();
			auto user = ledger::wallet::from_seed("123456");
			auto wallet = *server->compute_wallet(asset, 123456);
			for (auto& encoded_address : wallet.encoded_addresses)
				server->enable_link(asset, warden::wallet_link(user.public_key_hash, wallet.encoded_public_key, encoded_address.second)).expect("link activation error");

			auto link = warden::wallet_link::from_owner(user.public_key_hash);
			auto balance = coawait(server->calculate_balance(asset, link));
			auto info = wallet.as_schema();
			info->set("balance", var::string(balance ? balance->to_string().c_str() : "?"));
			term->jwrite_line(*info);

			if (false)
			{
				vector<warden::value_transfer> to = { warden::value_transfer(asset, "addr_test1vzpkkthr9azvuagxcf0m27qvzdad7n95jutgcdtglgmhdns998vsz", decimal("153")) };
				auto prepared_transaction = coawait(server->prepare_transaction(asset, link, to));
				for (auto& input : prepared_transaction->inputs)
				{
					algorithm::composition::accumulate_signature(input.alg, input.message.data(), input.message.size(), input.public_key, wallet.secret_key, input.signature).expect("signature accumulation error");
					algorithm::composition::accumulate_signature(input.alg, input.message.data(), input.message.size(), input.public_key, nullptr, input.signature).expect("signature finalization error");
				}

				auto finalized_transaction = server->finalize_transaction(asset, std::move(*prepared_transaction));
				term->jwrite_line(*finalized_transaction->as_schema());
				coawait(server->broadcast_transaction(asset, uint256_t(codec::hex_encode(*crypto::random_bytes(32)), 16), *finalized_transaction)).expect("transaction broadcast error");
			}

			coreturn_void;
		});

		int exit_code = control.launch();
		test_case.wait();
		if (os::process::has_debugger())
		{
			auto* term = console::get();
			term->write("\n");
			term->write_color(std_color::white, std_color::dark_green);
			term->fwrite("  WARDEN TEST FINISHED  ");
			term->clear_color();
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

				uint32_t type = 0;
				auto index = string();
				auto column = string();
				auto row = string();
				auto& state = args[1];
				if (state == "nonce")
				{
					type = states::account_nonce::as_instance_type();
					index = states::account_nonce::as_instance_index(owner);
				}
				else if (state == "program")
				{
					type = states::account_program::as_instance_type();
					index = states::account_program::as_instance_index(owner);
				}
				else if (state == "uniform")
				{
					if (args.size() < 4)
						goto not_valid;

					type = states::account_uniform::as_instance_type();
					index = states::account_uniform::as_instance_index(owner, codec::hex_decode(args[3]));
				}
				else if (state == "multiform")
				{
					if (args.size() < 5)
						goto not_valid;

					type = states::account_multiform::as_instance_type();
					column = states::account_multiform::as_instance_column(owner, codec::hex_decode(args[3]));
					row = states::account_multiform::as_instance_row(codec::hex_decode(args[4]));
				}
				else if (state == "delegation")
				{
					type = states::account_delegation::as_instance_type();
					index = states::account_delegation::as_instance_index(owner);
				}
				else if (state == "balance")
				{
					if (args.size() < 4)
						goto not_valid;

					type = states::account_balance::as_instance_type();
					column = states::account_balance::as_instance_column(owner);
					row = states::account_balance::as_instance_row(algorithm::asset::id_of_handle(args[3]));
				}

				auto response = index.empty() ? chain.get_multiform_by_composition(type, nullptr, column, row, 0) : chain.get_uniform_by_index(type, nullptr, index, 0);
				if (!response || !*response)
					goto not_found;

				auto data = (*response)->as_schema();
				term->jwrite_line(*data);
				continue;
			}
			else if (method == "validator")
			{
				if (args.size() < 3)
					goto not_valid;

				algorithm::pubkeyhash owner = { 0 };
				if (!algorithm::signing::decode_address(args[2], owner))
					goto not_valid;

				uint32_t type = 0;
				auto index = string();
				auto column = string();
				auto row = string();
				auto& state = args[1];
				if (state == "production")
				{
					type = states::validator_production::as_instance_type();
					column = states::validator_production::as_instance_column(owner);
					row = states::validator_production::as_instance_row();
				}
				else if (state == "participation")
				{
					if (args.size() < 4)
						goto not_valid;

					type = states::validator_participation::as_instance_type();
					column = states::validator_participation::as_instance_column(owner);
					row = states::validator_participation::as_instance_row(algorithm::asset::id_of_handle(args[3]));
				}
				else if (state == "attestation")
				{
					if (args.size() < 4)
						goto not_valid;

					type = states::validator_attestation::as_instance_type();
					column = states::validator_attestation::as_instance_column(owner);
					row = states::validator_attestation::as_instance_row(algorithm::asset::id_of_handle(args[3]));
				}

				auto response = index.empty() ? chain.get_multiform_by_composition(type, nullptr, column, row, 0) : chain.get_uniform_by_index(type, nullptr, index, 0);
				if (!response || !*response)
					goto not_found;

				auto data = (*response)->as_schema();
				term->jwrite_line(*data);
				continue;
			}
			else if (method == "depository")
			{
				if (args.size() < 3)
					goto not_valid;

				algorithm::pubkeyhash owner = { 0 };
				if (!algorithm::signing::decode_address(args[2], owner))
					goto not_valid;

				uint32_t type = 0;
				auto index = string();
				auto column = string();
				auto row = string();
				auto& state = args[1];
				if (state == "reward")
				{
					if (args.size() < 4)
						goto not_valid;

					type = states::depository_reward::as_instance_type();
					column = states::depository_reward::as_instance_column(owner);
					row = states::depository_reward::as_instance_row(algorithm::asset::id_of_handle(args[3]));
				}
				else if (state == "balance")
				{
					if (args.size() < 4)
						goto not_valid;

					type = states::depository_balance::as_instance_type();
					column = states::depository_balance::as_instance_column(owner);
					row = states::depository_balance::as_instance_row(algorithm::asset::id_of_handle(args[3]));
				}
				else if (state == "policy")
				{
					if (args.size() < 4)
						goto not_valid;

					type = states::depository_policy::as_instance_type();
					column = states::depository_policy::as_instance_column(owner);
					row = states::depository_policy::as_instance_row(algorithm::asset::id_of_handle(args[3]));
				}
				else if (state == "account")
				{
					if (args.size() < 5)
						goto not_valid;

					algorithm::pubkeyhash subject = { 0 };
					if (!algorithm::signing::decode_address(args[3], subject))
						goto not_valid;

					type = states::depository_account::as_instance_type();
					column = states::depository_account::as_instance_column(owner);
					row = states::depository_account::as_instance_row(algorithm::asset::id_of_handle(args[4]), subject);
				}

				auto response = index.empty() ? chain.get_multiform_by_composition(type, nullptr, column, row, 0) : chain.get_uniform_by_index(type, nullptr, index, 0);
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

				uint32_t type = 0;
				auto index = string();
				auto column = string();
				auto row = string();
				auto& state = args[1];
				if (state == "program")
				{
					if (args.size() < 3)
						goto not_valid;

					type = states::witness_program::as_instance_type();
					index = states::witness_program::as_instance_index(args[2]);
				}
				else if (state == "event")
				{
					if (args.size() < 3)
						goto not_valid;

					type = states::witness_event::as_instance_type();
					index = states::witness_event::as_instance_index(algorithm::encoding::decode_0xhex256(args[2]));
				}
				else if (state == "account")
				{
					if (args.size() < 5)
						goto not_valid;

					algorithm::pubkeyhash owner = { 0 };
					if (!algorithm::signing::decode_address(args[2], owner))
						goto not_valid;

					type = states::witness_account::as_instance_type();
					column = states::witness_account::as_instance_column(owner);
					row = states::witness_account::as_instance_row(algorithm::asset::id_of_handle(args[3]), args[4]);
				}
				else if (state == "transaction")
				{
					if (args.size() < 4)
						goto not_valid;

					type = states::witness_transaction::as_instance_type();
					index = states::witness_transaction::as_instance_index(algorithm::asset::id_of_handle(args[2]), args[3]);
				}

				auto response = index.empty() ? chain.get_multiform_by_composition(type, nullptr, column, row, 0) : chain.get_uniform_by_index(type, nullptr, index, 0);
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

				auto response3 = chain.get_block_state_hashset(response1->number);
				if (response3)
				{
					auto* hashes = data->set("state", var::set::array());
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
				if (current_number < chain.get_checkpoint_block_number().or_else(0))
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
					auto evaluation = ledger::block_evaluation();
					auto validation = validate ? next->validate(parent_block.address()) : expects_lr<void>(expectation::met);
					auto validity = next->verify_validity(parent_block.address());
					auto integrity = next->verify_integrity(parent_block.address(), validate ? &evaluation.state : nullptr);
					auto proof = next->as_proof(parent_block.address(), validate ? &evaluation.state : nullptr);
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

					if (validate)
					{
						for (auto& item : block_info->get("state")->get_childs())
							item->set("merkle_test", var::string(proof.has_state(algorithm::encoding::decode_0xhex256(item->get_var("hash").get_blob())) ? "passed" : "failed"));
					}

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
			term->write_color(std_color::white, std_color::dark_green);
			term->fwrite("  EXPLORER TEST FINISHED  ");
			term->clear_color();
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
		const size_t transaction_count = (size_t)ledger::block::get_transaction_limit();
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

		vector<tests::account> users;
		tests::blockchain_partial_coverage(&users);

		auto& [user1, user1_nonce] = users[0];
		auto chain = storages::chainstate(__func__);
		auto context = ledger::transaction_context();
		auto user1_addresses = *context.get_witness_accounts_by_purpose(user1.public_key_hash, states::witness_account::account_type::depository, 0, 128);
		auto user1_depository_address = std::find_if(user1_addresses.begin(), user1_addresses.end(), [](states::witness_account& item) { return item.asset == algorithm::asset::id_of("BTC"); });
		VI_PANIC(user1_depository_address != user1_addresses.end(), "user 1 depository address not found");

		auto gas_wallet = ledger::wallet::from_seed();
		transactions::transfer gas_transaction;
		gas_transaction.set_asset("BTC");
		gas_transaction.set_to(algorithm::encoding::to_subaddress(gas_wallet.public_key_hash), 0.1);
		VI_PANIC(gas_transaction.sign(user1.secret_key, user1_nonce, decimal::zero()), "transfer not signed");

		if (entropy == 0)
		{
			const decimal outgoing_account_balance = starting_account_balance / decimal(block_count * (transaction_count + 64));
			const decimal incoming_quantity = starting_account_balance;
			auto* depository_transaction = memory::init<transactions::depository_transaction>();
			depository_transaction->set_asset("BTC");
			depository_transaction->set_finalized_witness(883669,
				"222fc360affb804ad2c34bba2269b36a64a86f017d05a9a60b237e8587bfc52b",
				{ warden::value_transfer(depository_transaction->asset, "mmtubFoJvXrBuBUQFf1RrowXUbsiPDYnYS", decimal(incoming_quantity)) },
				{ warden::value_transfer(depository_transaction->asset, user1_depository_address->addresses.begin()->second, decimal(incoming_quantity)) });
			VI_PANIC(depository_transaction->sign(user1.secret_key, 0, decimal::zero()), "claim not signed");

			auto genesis = vector<uptr<ledger::transaction>>();
			genesis.push_back(depository_transaction);
			checkpoint(std::move(genesis), users);

			auto receiver = ledger::wallet::from_seed("000002");
			auto generate = [&]() -> vector<uptr<ledger::transaction>>
			{
				vector<uptr<ledger::transaction>> transactions;
				transactions.resize(transaction_count);
				parallel::wail_all(parallel::for_each(transactions.begin(), transactions.end(), ELEMENTS_FEW, [&](uptr<ledger::transaction>& item)
				{
					double balance = (double)(std::max<uint64_t>(1000, crypto::random() % 10000)) / 10000.0;

					auto* transaction = memory::init<transactions::transfer>();
					transaction->set_asset("BTC");
					transaction->set_gas(gas_transaction.gas_price, gas_transaction.gas_limit);
					transaction->set_to(algorithm::encoding::to_subaddress(receiver.public_key_hash), decimal(outgoing_account_balance).truncate(12) * decimal(balance));
					VI_PANIC(transaction->sign(user1.secret_key, user1_nonce++), "transfer not signed");
					item = transaction;
				}));
				VI_SORT(transactions.begin(), transactions.end(), [](const uptr<ledger::transaction>& a, const uptr<ledger::transaction>& b) { return a->nonce < b->nonce; });
				return transactions;
			};

			auto transactions = generate();
			for (size_t i = 0; i < block_count; i++)
			{
				auto next_transactions = cotask<vector<uptr<ledger::transaction>>>([&]() { return generate(); });
				checkpoint(std::move(transactions), users);
				transactions = std::move(next_transactions.get());
			}
		}
		else if (entropy == 1)
		{
			const size_t sender_count = 16;
			const size_t receiver_count = 32;
			const decimal outgoing_account_balance = starting_account_balance / decimal(block_count * (transaction_count + 64) * sender_count);
			const decimal incoming_quantity = starting_account_balance * sender_count;
			auto* depository_transaction = memory::init<transactions::depository_transaction>();
			depository_transaction->set_asset("BTC");
			depository_transaction->set_finalized_witness(883669,
				"222fc360affb804ad2c34bba2269b36a64a86f017d05a9a60b237e8587bfc52b",
				{ warden::value_transfer(depository_transaction->asset, "mmtubFoJvXrBuBUQFf1RrowXUbsiPDYnYS", decimal(incoming_quantity)) },
				{ warden::value_transfer(depository_transaction->asset, user1_depository_address->addresses.begin()->second, decimal(incoming_quantity)) });
			VI_PANIC(depository_transaction->sign(user1.secret_key, 0, decimal::zero()), "claim not signed");

			auto genesis = vector<uptr<ledger::transaction>>();
			genesis.push_back(depository_transaction);
			checkpoint(std::move(genesis), users);

			vector<tests::account> senders;
			senders.reserve(sender_count);
			for (size_t i = 0; i < sender_count; i++)
				senders.emplace_back(tests::account(ledger::wallet::from_seed(stringify::text("00001%i", (int)i)), 1));

			vector<tests::account> receivers;
			receivers.reserve(receiver_count);
			for (size_t i = 0; i < receiver_count; i++)
				receivers.emplace_back(tests::account(ledger::wallet::from_seed(stringify::text("00002%i", (int)i)), 1));

			auto* transfer = memory::init<transactions::transfer>();
			transfer->set_asset("BTC");
			for (auto& sender : senders)
				transfer->set_to(algorithm::encoding::to_subaddress(sender.wallet.public_key_hash), starting_account_balance);
			transfer->set_gas(decimal::zero(), ledger::block::get_gas_limit());
			VI_PANIC(transfer->sign(user1.secret_key, user1_nonce++), "transfer not signed");

			genesis = vector<uptr<ledger::transaction>>();
			genesis.push_back(transfer);
			checkpoint(std::move(genesis), users);

			auto generate = [&]() -> vector<uptr<ledger::transaction>>
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
					transaction->set_gas(gas_transaction.gas_price, gas_transaction.gas_limit);
					transaction->set_to(algorithm::encoding::to_subaddress(receiver.wallet.public_key_hash), decimal(outgoing_account_balance).truncate(12) * decimal(balance));
					VI_PANIC(transaction->sign(sender.wallet.secret_key, sender.nonce++), "transfer not signed");
					item = transaction;
				}));
				VI_SORT(transactions.begin(), transactions.end(), [](const uptr<ledger::transaction>& a, const uptr<ledger::transaction>& b) { return a->nonce < b->nonce; });
				return transactions;
			};

			auto transactions = generate();
			for (size_t i = 0; i < block_count; i++)
			{
				auto next_transactions = cotask<vector<uptr<ledger::transaction>>>([&]() { return generate(); });
				checkpoint(std::move(transactions), users);
				transactions = std::move(next_transactions.get());
			}
		}
		else
		{
			const size_t sender_count = transaction_count;
			const decimal outgoing_account_balance = starting_account_balance / decimal(block_count * (transaction_count + 64) * sender_count);
			const decimal incoming_quantity = starting_account_balance * sender_count * 2;
			auto* depository_transaction = memory::init<transactions::depository_transaction>();
			depository_transaction->set_asset("BTC");
			depository_transaction->set_finalized_witness(883669,
				"222fc360affb804ad2c34bba2269b36a64a86f017d05a9a60b237e8587bfc52b",
				{ warden::value_transfer(depository_transaction->asset, "mmtubFoJvXrBuBUQFf1RrowXUbsiPDYnYS", decimal(incoming_quantity)) },
				{ warden::value_transfer(depository_transaction->asset, user1_depository_address->addresses.begin()->second, decimal(incoming_quantity)) });
			VI_PANIC(depository_transaction->sign(user1.secret_key, 0, decimal::zero()), "claim not signed");

			auto genesis = vector<uptr<ledger::transaction>>();
			genesis.push_back(depository_transaction);
			checkpoint(std::move(genesis), users);

			vector<tests::account> senders;
			senders.reserve(sender_count);
			for (size_t i = 0; i < sender_count; i++)
				senders.emplace_back(tests::account({ ledger::wallet::from_seed(stringify::text("00001%i", (int)i)), 1 }));

			auto* transfer = memory::init<transactions::transfer>();
			transfer->set_asset("BTC");
			for (auto& sender : senders)
				transfer->set_to(algorithm::encoding::to_subaddress(sender.wallet.public_key_hash), starting_account_balance);
			transfer->set_gas(decimal::zero(), ledger::block::get_gas_limit());
			VI_PANIC(transfer->sign(user1.secret_key, user1_nonce++), "transfer not signed");

			genesis = vector<uptr<ledger::transaction>>();
			genesis.push_back(transfer);
			checkpoint(std::move(genesis), users);

			auto generate = [&]() -> vector<uptr<ledger::transaction>>
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
					transaction->set_gas(gas_transaction.gas_price, gas_transaction.gas_limit);
					transaction->set_to(algorithm::encoding::to_subaddress(receiver), decimal(outgoing_account_balance).truncate(12) * decimal(balance));
					VI_PANIC(transaction->sign(sender.wallet.secret_key, sender.nonce++), "transfer not signed");
					item = transaction;
				}));
				VI_SORT(transactions.begin(), transactions.end(), [](const uptr<ledger::transaction>& a, const uptr<ledger::transaction>& b) { return a->nonce < b->nonce; });
				return transactions;
			};

			auto transactions = generate();
			for (size_t i = 0; i < block_count; i++)
			{
				auto next_transactions = cotask<vector<uptr<ledger::transaction>>>([&]() { return generate(); });
				checkpoint(std::move(transactions), users);
				transactions = std::move(next_transactions.get());
			}
		}

		queue->stop();
		if (os::process::has_debugger())
		{
			auto* term = console::get();
			term->write("\n");
			term->write_color(std_color::white, std_color::dark_green);
			term->fwrite("  BENCHMARK TEST FINISHED  ");
			term->clear_color();
			term->write("\n\n");
			term->read_char();
		}

		return 0;
	}
	/* test case runner for regression testing */
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
			{ "cryptography / wallet encryption", &tests::cryptography_wallet_encryption },
			{ "cryptography / wallet address", &tests::cryptography_wallet_address },
			{ "cryptography / transaction", &tests::cryptography_transaction },
			{ "cryptography / merkle tree", &tests::cryptography_merkle_tree },
			{ "cryptography / multichain wallet", &tests::cryptography_multichain_wallet },
			{ "cryptography / multichain mpc", &tests::cryptography_multichain_mpc },
			{ "cryptography / multichain transaction", &tests::cryptography_multichain_transaction },
			{ "blockchain / full coverage", std::bind(&tests::blockchain_full_coverage, (vector<tests::account>*)nullptr) },
			{ "blockchain / verification", &tests::blockchain_verification },
			{ "blockchain / partial coverage", std::bind(&tests::blockchain_partial_coverage, (vector<tests::account>*)nullptr) },
			{ "blockchain / verification", &tests::blockchain_verification },
			{ "blockchain / gas estimation", &tests::blockchain_gas_estimation },
		};
		for (size_t i = 0; i < cases.size(); i++)
		{
			auto& condition = cases[i];
			term->write_color(std_color::black, std_color::yellow);
			term->fwrite("  ===>  %s  <===  ", condition.first.data());
			term->clear_color();
			term->write_char('\n');
			term->capture_time();

			condition.second();

			double time = term->get_captured_time();
			term->write_color(std_color::white, std_color::dark_green);
			term->fwrite("  TEST PASS %.1fms %.2f%%  ", time, 100.0 * (double)(i + 1) / (double)cases.size());
			term->clear_color();
			term->write("\n\n");
		}

		if (os::process::has_debugger())
		{
			auto* term = console::get();
			term->write_color(std_color::white, std_color::dark_green);
			term->fwrite("  REGRESSION TEST FINISHED  ");
			term->clear_color();
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