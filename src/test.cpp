#include "tangent/validator/entrypoints.hpp"
#include "tangent/validator/storage/oraclestate.h"
#include "tangent/validator/storage/mempoolstate.h"
#include "tangent/policy/compositions.h"
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
		account(account&& other) noexcept : wallet(std::move(other.wallet)), nonce(other.nonce.load())
		{
		};
		account(const account& other) : wallet(other.wallet), nonce(other.nonce.load())
		{
		}
		account& operator= (account&& other) noexcept
		{
			if (&other == this)
				return *this;

			wallet = std::move(other.wallet);
			nonce = other.nonce.load();
			return *this;
		}
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
			transfer_ethereum->set_to(user2.public_key_hash, 0.1);
			transfer_ethereum->set_to(user2.public_key_hash, 0.2);
			transfer_ethereum->set_to(user2.public_key_hash, 0.3);
			transfer_ethereum->set_to(user2.public_key_hash, 0.4);
			transfer_ethereum->set_to(user2.public_key_hash, 0.5);
			transfer_ethereum->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
			transactions.push_back(transfer_ethereum);

			auto user_test = ledger::wallet::from_seed(user1.secret_key.view());
			auto* transfer_ripple = memory::init<transactions::transfer>();
			transfer_ripple->set_asset("XRP");
			transfer_ripple->set_to(user2.public_key_hash, 9.0);
			transfer_ripple->set_to(user2.public_key_hash, 1.0);
			transfer_ripple->set_to(user_test.public_key_hash, 5.0);
			transfer_ripple->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
			transactions.push_back(transfer_ripple);

			auto* transfer_bitcoin = memory::init<transactions::transfer>();
			transfer_bitcoin->set_asset("BTC");
			transfer_bitcoin->set_to(user2.public_key_hash, 0.1);
			transfer_bitcoin->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
			transactions.push_back(transfer_bitcoin);
		}
		static void account_transfer_stage_2(vector<uptr<ledger::transaction>>& transactions, vector<account>& users)
		{
			auto& [user1, user1_nonce] = users[0];
			auto& [user2, user2_nonce] = users[1];
			auto* transfer_ethereum = memory::init<transactions::transfer>();
			transfer_ethereum->set_asset("ETH");
			transfer_ethereum->set_to(user1.public_key_hash, 0.01);
			transfer_ethereum->set_to(user1.public_key_hash, 0.02);
			transfer_ethereum->set_to(user1.public_key_hash, 0.03);
			transfer_ethereum->set_to(user1.public_key_hash, 0.04);
			transfer_ethereum->set_to(user1.public_key_hash, 0.05);
			transfer_ethereum->sign(user2.secret_key, user2_nonce++, std::string_view("0.00000001")).expect("pre-validation failed");
			transactions.push_back(transfer_ethereum);
			
			auto user_test = ledger::wallet::from_seed(user1.secret_key.view());
			auto* transfer_ripple = memory::init<transactions::transfer>();
			transfer_ripple->set_asset("XRP");
			transfer_ripple->set_to(user1.public_key_hash, 5.0);
			transfer_ripple->sign(user_test.secret_key, 0, decimal::zero()).expect("pre-validation failed");
			transactions.push_back(transfer_ripple);
		}
		static void account_transfer_to_account(vector<uptr<ledger::transaction>>& transactions, vector<account>& users, size_t user_id, const algorithm::asset_id& asset, const std::string_view& address, const decimal& value)
		{
			auto& [user1, user1_nonce] = users[user_id];
			algorithm::pubkeyhash_t public_key_hash;
			algorithm::signing::decode_address(address, public_key_hash);

			auto* transfer_asset = memory::init<transactions::transfer>();
			transfer_asset->asset = asset;
			transfer_asset->set_to(public_key_hash, value);
			transfer_asset->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
			transactions.push_back(transfer_asset);
		}
		static void account_transaction_rollup(vector<uptr<ledger::transaction>>& transactions, vector<account>& users)
		{
			auto& [user1, user1_nonce] = users[0];
			auto& [user2, user2_nonce] = users[1];
			auto* multi_asset_rollup = memory::init<transactions::rollup>();
			multi_asset_rollup->set_asset("ETH");

			auto transfer_ethereum1 = transactions::transfer();
			transfer_ethereum1.set_to(user2.public_key_hash, 0.1);
			VI_PANIC(multi_asset_rollup->import_internal_transaction(transfer_ethereum1, user1.secret_key), "authentication failed");

			auto transfer_ethereum2 = transactions::transfer();
			transfer_ethereum2.set_to(user2.public_key_hash, 0.2);
			VI_PANIC(multi_asset_rollup->import_internal_transaction(transfer_ethereum2, user1.secret_key), "authentication failed");

			auto transfer_ethereum3 = transactions::transfer();
			transfer_ethereum3.set_to(user1.public_key_hash, 0.2);
			VI_PANIC(multi_asset_rollup->import_external_transaction(transfer_ethereum3, user2.secret_key, user2_nonce++), "authentication failed");

			auto transfer_ripple1 = transactions::transfer();
			transfer_ripple1.set_asset("XRP");
			transfer_ripple1.set_to(user2.public_key_hash, 1);
			VI_PANIC(multi_asset_rollup->import_internal_transaction(transfer_ripple1, user1.secret_key), "authentication failed");

			auto transfer_ripple2 = transactions::transfer();
			transfer_ripple2.set_asset("XRP");
			transfer_ripple2.set_to(user2.public_key_hash, 2);
			VI_PANIC(multi_asset_rollup->import_internal_transaction(transfer_ripple2, user1.secret_key), "authentication failed");

			auto transfer_ripple3 = transactions::transfer();
			transfer_ripple3.set_asset("XRP");
			transfer_ripple3.set_to(user1.public_key_hash, 2);
			VI_PANIC(multi_asset_rollup->import_external_transaction(transfer_ripple3, user2.secret_key, user2_nonce++), "authentication failed");

			auto transfer_bitcoin1 = transactions::transfer();
			transfer_bitcoin1.set_asset("BTC");
			transfer_bitcoin1.set_to(user2.public_key_hash, 0.001);
			VI_PANIC(multi_asset_rollup->import_internal_transaction(transfer_bitcoin1, user1.secret_key), "authentication failed");

			auto transfer_bitcoin2 = transactions::transfer();
			transfer_bitcoin2.set_asset("BTC");
			transfer_bitcoin2.set_to(user2.public_key_hash, 0.002);
			VI_PANIC(multi_asset_rollup->import_internal_transaction(transfer_bitcoin2, user1.secret_key), "authentication failed");

			auto transfer_bitcoin3 = transactions::transfer();
			transfer_bitcoin3.set_asset("BTC");
			transfer_bitcoin3.set_to(user1.public_key_hash, 0.002);
			VI_PANIC(multi_asset_rollup->import_external_transaction(transfer_bitcoin3, user2.secret_key, user2_nonce++), "authentication failed");

			multi_asset_rollup->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
			transactions.push_back(multi_asset_rollup);
		}
		static void account_upgrade_stage_1(vector<uptr<ledger::transaction>>& transactions, vector<account>& users, vector<algorithm::pubkeyhash_t>* contracts)
		{
			auto& [user1, user1_nonce] = users[0];
			std::string_view token_program = VI_STRINGIFY((
			class token_storage
			{
				address deployer;
				address contract;
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

			varying<token_storage> token;
			mapping<address, uint256> balances;

			token_storage construct(instrset::rwptr@, const string&in symbol, const string&in name, const address&in admin, const uint256&in value)
			{
				token_storage new_token;
				new_token.deployer = tx::from();
				new_token.contract = tx::to();
				new_token.account = admin;
				new_token.name = name;
				new_token.symbol = symbol;
				new_token.decimals = 2;
				new_token.supply = value;
				token = new_token;

				balances.insert_if(value > 0, token.ref.account, value);
				return token.ref;
			}
			token_transfer transfer(instrset::rwptr@, const address&in to, const uint256&in value)
			{
				address from = tx::from();
				uint256 input = balance_of(null, from);
				uint256 output = balance_of(null, to);
				uint256 from_delta = input - value, to_delta = output + value;
				require(from_delta <= input, string::from(from) + ": illegal operation - insufficient balance");
				require(to_delta >= output, string::from(to) + ": illegal operation - balance overflow");
				balances.insert_if(from_delta > 0, from, from_delta);
				balances.insert_if(to_delta > 0, to, to_delta);

				token_transfer event;
				event.from = from;
				event.to = to;
				event.value = value;
				return event;
			}
			uint256 mint(instrset::rwptr@, const uint256&in value)
			{
				require(token.ref.account == tx::from(), "illegal operation - operation not permitted");
				uint256 output = balance_of(null, token.ref.account);
				uint256 supply_delta = token.ref.supply + value;
				uint256 to_delta = output + value;
				require(supply_delta >= token.ref.supply, string::from(tx::to()) + ": illegal operation - token supply overflow");
				require(to_delta >= output, string::from(token.ref.account) + ": illegal operation - balance overflow");

				token_storage new_token = token.ref;
				new_token.supply = supply_delta;
				token = new_token;

				balances.insert_if(to_delta > 0, token.ref.account, to_delta);
				return to_delta;
			}
			uint256 burn(instrset::rwptr@, const uint256&in value)
			{
				require(token.ref.account == tx::from(), "illegal operation - operation not permitted");
				uint256 output = balance_of(null, token.ref.account);
				uint256 supply_delta = token.ref.supply - value;
				uint256 to_delta = output - value;
				require(supply_delta <= token.ref.supply, "token supply will underflow (" + string::from(token.ref.supply) + " < " + string::from(value) + ")");
				require(to_delta <= output, "account balance will underflow (" + string::from(output) + " < " + string::from(value) + ")");

				token_storage new_token = token.ref;
				new_token.supply = supply_delta;
				token = new_token;

				balances.insert_if(to_delta > 0, token.ref.account, to_delta);
				return to_delta;
			}
			uint256 balance_of(instrset::rptr@, const address&in account)
			{
				return balances.has(account) ? balances[account] : 0;
			}
			token_storage info(instrset::rptr@)
			{
				return token.ref;
			}));
			std::string_view bridge_program = VI_STRINGIFY((
			varying<address> token_account;

			void construct(instrset::rwptr@, const address&in new_token_account)
			{
				token_account = new_token_account;
			}
			uint256 balance_of_test_token(instrset::rptr@)
			{
				return token_account.ref.call<uint256>("uint256 balance_of(instrset::rptr@, const address&in)", tx::from());
			}));

			auto* upgrade_ethereum1 = memory::init<transactions::upgrade>();
			upgrade_ethereum1->set_asset("ETH");
			upgrade_ethereum1->from_program(token_program.substr(1, token_program.size() - 2), { format::variable("TT0"), format::variable("Test Token 0"), format::variable(user1.get_address()), format::variable(1000000u) });
			upgrade_ethereum1->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
			transactions.push_back(upgrade_ethereum1);
			contracts->push_back(upgrade_ethereum1->get_account());

			auto* upgrade_ethereum2 = memory::init<transactions::upgrade>();
			upgrade_ethereum2->set_asset("ETH");
			upgrade_ethereum2->from_program(bridge_program.substr(1, bridge_program.size() - 2), { format::variable(contracts->back().view()) });
			upgrade_ethereum2->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
			transactions.push_back(upgrade_ethereum2);
			contracts->push_back(upgrade_ethereum2->get_account());
		}
		static void account_upgrade_stage_2(vector<uptr<ledger::transaction>>& transactions, vector<account>& users, vector<algorithm::pubkeyhash_t>* contracts)
		{
			auto context = ledger::transaction_context();
			auto& [user2, user2_nonce] = users[1];
			auto* upgrade_ethereum1 = memory::init<transactions::upgrade>();
			upgrade_ethereum1->set_asset("ETH");
			upgrade_ethereum1->from_hashcode(context.get_account_program(contracts->at(0))->hashcode, { format::variable("TT1"), format::variable("Test Token 1"), format::variable(user2.get_address()), format::variable(1000000u) });
			upgrade_ethereum1->sign(user2.secret_key, user2_nonce++, decimal::zero()).expect("pre-validation failed");
			transactions.push_back(upgrade_ethereum1);
			contracts->push_back(upgrade_ethereum1->get_account());

			auto* upgrade_ethereum2 = memory::init<transactions::upgrade>();
			upgrade_ethereum2->set_asset("ETH");
			upgrade_ethereum2->from_hashcode(context.get_account_program(contracts->at(1))->hashcode, { format::variable(contracts->back().view()) });
			upgrade_ethereum2->sign(user2.secret_key, user2_nonce++, decimal::zero()).expect("pre-validation failed");
			transactions.push_back(upgrade_ethereum2);
			contracts->push_back(upgrade_ethereum2->get_account());
		}
		static void account_call(vector<uptr<ledger::transaction>>& transactions, vector<account>& users, vector<algorithm::pubkeyhash_t>* contracts)
		{
			auto& [user1, user1_nonce] = users[0];
			auto& [user2, user2_nonce] = users[1];
			auto* call_ethereum1 = memory::init<transactions::call>();
			call_ethereum1->set_asset("ETH");
			call_ethereum1->program_call(contracts->at(0), decimal::zero(), "transfer", { format::variable(user2.public_key_hash.view()), format::variable(250000u) });
			call_ethereum1->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
			transactions.push_back(call_ethereum1);

			auto* call_ethereum2 = memory::init<transactions::call>();
			call_ethereum2->set_asset("ETH");
			call_ethereum2->program_call(contracts->at(0), decimal::zero(), "info", { });
			call_ethereum2->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
			transactions.push_back(call_ethereum2);

			auto* call_ethereum3 = memory::init<transactions::call>();
			call_ethereum3->set_asset("ETH");
			call_ethereum3->program_call(contracts->at(2), decimal::zero(), "transfer", { format::variable(user1.public_key_hash.view()), format::variable(250000u) });
			call_ethereum3->sign(user2.secret_key, user2_nonce++, decimal::zero()).expect("pre-validation failed");
			transactions.push_back(call_ethereum3);

			auto* call_ethereum4 = memory::init<transactions::call>();
			call_ethereum4->set_asset("ETH");
			call_ethereum4->program_call(contracts->at(2), decimal::zero(), "info", { });
			call_ethereum4->sign(user2.secret_key, user2_nonce++, decimal::zero()).expect("pre-validation failed");
			transactions.push_back(call_ethereum4);

			auto* call_bitcoin1 = memory::init<transactions::call>();
			call_bitcoin1->set_asset("BTC");
			call_bitcoin1->program_call(contracts->at(1), decimal::zero(), "balance_of_test_token", { });
			call_bitcoin1->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
			transactions.push_back(call_bitcoin1);

			auto* call_bitcoin2 = memory::init<transactions::call>();
			call_bitcoin2->set_asset("BTC");
			call_bitcoin2->program_call(contracts->at(3), decimal::zero(), "balance_of_test_token", { });
			call_bitcoin2->sign(user2.secret_key, user2_nonce++, decimal::zero()).expect("pre-validation failed");
			transactions.push_back(call_bitcoin2);
		}
		static void validator_registration_full(vector<uptr<ledger::transaction>>& transactions, vector<account>& users)
		{
			auto& [user1, user1_nonce] = users[0];
			auto& [user2, user2_nonce] = users[1];
			auto* validator_adjustment_user1 = memory::init<transactions::validator_adjustment>();
			validator_adjustment_user1->set_asset("BTC");
			validator_adjustment_user1->enable_block_production();
			validator_adjustment_user1->allocate_attestation_stake(algorithm::asset::id_of("ETH"), decimal::zero());
			validator_adjustment_user1->allocate_attestation_stake(algorithm::asset::id_of("XRP"), decimal::zero());
			validator_adjustment_user1->allocate_attestation_stake(algorithm::asset::id_of("BTC"), decimal::zero());
			validator_adjustment_user1->allocate_participation_stake(algorithm::asset::id_of("ETH"), decimal::zero());
			validator_adjustment_user1->allocate_participation_stake(algorithm::asset::id_of("XRP"), decimal::zero());
			validator_adjustment_user1->allocate_participation_stake(algorithm::asset::id_of("BTC"), decimal::zero());
			validator_adjustment_user1->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
			transactions.push_back(validator_adjustment_user1);

			auto* validator_adjustment_user2 = memory::init<transactions::validator_adjustment>();
			validator_adjustment_user2->set_asset("BTC");
			validator_adjustment_user2->enable_block_production();
			validator_adjustment_user2->allocate_attestation_stake(algorithm::asset::id_of("ETH"), decimal::zero());
			validator_adjustment_user2->allocate_attestation_stake(algorithm::asset::id_of("XRP"), decimal::zero());
			validator_adjustment_user2->allocate_attestation_stake(algorithm::asset::id_of("BTC"), decimal::zero());
			validator_adjustment_user2->allocate_participation_stake(algorithm::asset::id_of("ETH"), decimal::zero());
			validator_adjustment_user2->allocate_participation_stake(algorithm::asset::id_of("XRP"), decimal::zero());
			validator_adjustment_user2->allocate_participation_stake(algorithm::asset::id_of("BTC"), decimal::zero());
			validator_adjustment_user2->sign(user2.secret_key, user2_nonce++, decimal::zero()).expect("pre-validation failed");
			transactions.push_back(validator_adjustment_user2);
		}
		static void validator_registration_partial(vector<uptr<ledger::transaction>>& transactions, vector<account>& users)
		{
			auto& [user1, user1_nonce] = users[0];
			auto* validator_adjustment_user1 = memory::init<transactions::validator_adjustment>();
			validator_adjustment_user1->set_asset("BTC");
			validator_adjustment_user1->enable_block_production();
			validator_adjustment_user1->allocate_attestation_stake(algorithm::asset::id_of("ETH"), decimal::zero());
			validator_adjustment_user1->allocate_attestation_stake(algorithm::asset::id_of("XRP"), decimal::zero());
			validator_adjustment_user1->allocate_attestation_stake(algorithm::asset::id_of("BTC"), decimal::zero());
			validator_adjustment_user1->allocate_participation_stake(algorithm::asset::id_of("ETH"), decimal::zero());
			validator_adjustment_user1->allocate_participation_stake(algorithm::asset::id_of("XRP"), decimal::zero());
			validator_adjustment_user1->allocate_participation_stake(algorithm::asset::id_of("BTC"), decimal::zero());
			validator_adjustment_user1->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
			transactions.push_back(validator_adjustment_user1);
		}
		static void validator_enable_validator(vector<uptr<ledger::transaction>>& transactions, vector<account>& users, size_t user_id, bool block_production, bool tx_attestation, bool mpc_participation)
		{
			auto& [user1, user1_nonce] = users[user_id];
			auto* validator_adjustment_user1 = memory::init<transactions::validator_adjustment>();
			validator_adjustment_user1->set_asset("BTC");
			if (block_production)
				validator_adjustment_user1->enable_block_production();
			if (tx_attestation)
			{
				validator_adjustment_user1->allocate_attestation_stake(algorithm::asset::id_of("ETH"), decimal::zero());
				validator_adjustment_user1->allocate_attestation_stake(algorithm::asset::id_of("XRP"), decimal::zero());
				validator_adjustment_user1->allocate_attestation_stake(algorithm::asset::id_of("BTC"), decimal::zero());
			}
			if (mpc_participation)
			{
				validator_adjustment_user1->allocate_participation_stake(algorithm::asset::id_of("ETH"), decimal::zero());
				validator_adjustment_user1->allocate_participation_stake(algorithm::asset::id_of("XRP"), decimal::zero());
				validator_adjustment_user1->allocate_participation_stake(algorithm::asset::id_of("BTC"), decimal::zero());
			}
			validator_adjustment_user1->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
			transactions.push_back(validator_adjustment_user1);
		}
		static void validator_disable_validator(vector<uptr<ledger::transaction>>& transactions, vector<account>& users, size_t user_id, bool block_production, bool tx_attestation, bool mpc_participation)
		{
			auto& [user1, user1_nonce] = users[user_id];
			auto* validator_adjustment_user1 = memory::init<transactions::validator_adjustment>();
			validator_adjustment_user1->set_asset("BTC");
			if (block_production)
				validator_adjustment_user1->disable_block_production();
			if (tx_attestation)
			{
				validator_adjustment_user1->disable_attestation(algorithm::asset::id_of("ETH"));
				validator_adjustment_user1->disable_attestation(algorithm::asset::id_of("XRP"));
				validator_adjustment_user1->disable_attestation(algorithm::asset::id_of("BTC"));
			}
			if (mpc_participation)
			{
				validator_adjustment_user1->disable_participation(algorithm::asset::id_of("ETH"));
				validator_adjustment_user1->disable_participation(algorithm::asset::id_of("XRP"));
				validator_adjustment_user1->disable_participation(algorithm::asset::id_of("BTC"));
			}
			validator_adjustment_user1->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
			transactions.push_back(validator_adjustment_user1);
		}
		static void depository_registration_full(vector<uptr<ledger::transaction>>& transactions, vector<account>& users)
		{
			auto& [user1, user1_nonce] = users[0];
			auto& [user2, user2_nonce] = users[1];
			auto* depository_adjustment_ethereum = memory::init<transactions::depository_adjustment>();
			depository_adjustment_ethereum->set_asset("ETH");
			depository_adjustment_ethereum->set_reward(0.0012, 0.0012);
			depository_adjustment_ethereum->set_security(2, decimal::zero(), true, true);
			depository_adjustment_ethereum->sign(user2.secret_key, user2_nonce++, decimal::zero()).expect("pre-validation failed");
			transactions.push_back(depository_adjustment_ethereum);

			auto* depository_adjustment_ripple1 = memory::init<transactions::depository_adjustment>();
			depository_adjustment_ripple1->set_asset("XRP");
			depository_adjustment_ripple1->set_reward(1.0, 1.0);
			depository_adjustment_ripple1->set_security(2, decimal::zero(), true, true);
			depository_adjustment_ripple1->sign(user2.secret_key, user2_nonce++, decimal::zero()).expect("pre-validation failed");
			transactions.push_back(depository_adjustment_ripple1);

			auto* depository_adjustment_ripple2 = memory::init<transactions::depository_adjustment>();
			depository_adjustment_ripple2->set_asset("XRP");
			depository_adjustment_ripple2->set_reward(0, 0);
			depository_adjustment_ripple2->set_security(2, decimal::zero(), true, true);
			depository_adjustment_ripple2->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
			transactions.push_back(depository_adjustment_ripple2);

			auto* depository_adjustment_bitcoin = memory::init<transactions::depository_adjustment>();
			depository_adjustment_bitcoin->set_asset("BTC");
			depository_adjustment_bitcoin->set_reward(0.000025, 0.000025);
			depository_adjustment_bitcoin->set_security(2, decimal::zero(), true, true);
			depository_adjustment_bitcoin->sign(user2.secret_key, user2_nonce++, decimal::zero()).expect("pre-validation failed");
			transactions.push_back(depository_adjustment_bitcoin);
		}
		static void depository_registration_partial(vector<uptr<ledger::transaction>>& transactions, vector<account>& users)
		{
			auto& [user1, user1_nonce] = users[0];
			auto* depository_adjustment_bitcoin = memory::init<transactions::depository_adjustment>();
			depository_adjustment_bitcoin->set_asset("BTC");
			depository_adjustment_bitcoin->set_reward(0.00001, 0.000025);
			depository_adjustment_bitcoin->set_security(1, decimal::zero(), true, true);
			depository_adjustment_bitcoin->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
			transactions.push_back(depository_adjustment_bitcoin);

			auto* depository_adjustment_ethereum = memory::init<transactions::depository_adjustment>();
			depository_adjustment_ethereum->set_asset("ETH");
			depository_adjustment_ethereum->set_reward(0.0012, 0.0012);
			depository_adjustment_ethereum->set_security(1, decimal::zero(), true, true);
			depository_adjustment_ethereum->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
			transactions.push_back(depository_adjustment_ethereum);
		}
		static void depository_account_registration_full_stage_1(vector<uptr<ledger::transaction>>& transactions, vector<account>& users)
		{
			auto& [user1, user1_nonce] = users[0];
			auto& [user2, user2_nonce] = users[1];
			auto* depository_account_ethereum = memory::init<transactions::depository_account>();
			depository_account_ethereum->set_asset("ETH");
			depository_account_ethereum->set_manager(user2.public_key_hash);
			depository_account_ethereum->sign(user2.secret_key, user2_nonce++, decimal::zero()).expect("pre-validation failed");
			transactions.push_back(depository_account_ethereum);

			auto* depository_account_ripple1 = memory::init<transactions::depository_account>();
			depository_account_ripple1->set_asset("XRP");
			depository_account_ripple1->set_routing_address("rUBqz2JiRCT3gYZBnm28y5ME7e5UpSm2ok");
			depository_account_ripple1->set_manager(user1.public_key_hash);
			depository_account_ripple1->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
			transactions.push_back(depository_account_ripple1);

			auto* depository_account_ripple2 = memory::init<transactions::depository_account>();
			depository_account_ripple2->set_asset("XRP");
			depository_account_ripple2->set_manager(user2.public_key_hash);
			depository_account_ripple2->sign(user2.secret_key, user2_nonce++, decimal::zero()).expect("pre-validation failed");
			transactions.push_back(depository_account_ripple2);
		}
		static void depository_account_registration_full_stage_2(vector<uptr<ledger::transaction>>& transactions, vector<account>& users)
		{
			auto& [user1, user1_nonce] = users[0];
			auto& [user2, user2_nonce] = users[1];
			auto* depository_account_ethereum = memory::init<transactions::depository_account>();
			depository_account_ethereum->set_asset("ETH");
			depository_account_ethereum->set_routing_address("0xCa0dfDdBb1cBD7B5A08E9173D9bbE5722138d4d5");
			depository_account_ethereum->set_manager(user2.public_key_hash);
			depository_account_ethereum->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
			transactions.push_back(depository_account_ethereum);

			auto* depository_account_ripple = memory::init<transactions::depository_account>();
			depository_account_ripple->set_asset("XRP");
			depository_account_ripple->set_manager(user2.public_key_hash);
			depository_account_ripple->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
			transactions.push_back(depository_account_ripple);

			auto* depository_account_bitcoin = memory::init<transactions::depository_account>();
			depository_account_bitcoin->set_asset("BTC");
			depository_account_bitcoin->set_routing_address("mmtubFoJvXrBuBUQFf1RrowXUbsiPDYnYS");
			depository_account_bitcoin->set_manager(user2.public_key_hash);
			depository_account_bitcoin->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
			transactions.push_back(depository_account_bitcoin);
		}
		static void depository_account_registration_partial(vector<uptr<ledger::transaction>>& transactions, vector<account>& users)
		{
			auto& [user1, user1_nonce] = users[0];
			auto* depository_account_bitcoin = memory::init<transactions::depository_account>();
			depository_account_bitcoin->set_asset("BTC");
			depository_account_bitcoin->set_routing_address("mmtubFoJvXrBuBUQFf1RrowXUbsiPDYnYS");
			depository_account_bitcoin->set_manager(user1.public_key_hash);
			depository_account_bitcoin->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
			transactions.push_back(depository_account_bitcoin);

			auto* depository_account_ethereum = memory::init<transactions::depository_account>();
			depository_account_ethereum->set_asset("ETH");
			depository_account_ethereum->set_routing_address("0xCa0dfDdBb1cBD7B5A08E9173D9bbE5722138d4d5");
			depository_account_ethereum->set_manager(user1.public_key_hash);
			depository_account_ethereum->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
			transactions.push_back(depository_account_ethereum);
		}
		static void depository_attestation_registration_full(vector<uptr<ledger::transaction>>& transactions, vector<account>& users)
		{
			auto& [user1, user1_nonce] = users[0];
			auto& [user2, user2_nonce] = users[1];
			auto context = ledger::transaction_context();
			auto owner_addresses = *context.get_witness_accounts_by_purpose(user1.public_key_hash, states::witness_account::account_type::depository, 0, 128);
			auto manager_addresses = *context.get_witness_accounts_by_purpose(user2.public_key_hash, states::witness_account::account_type::depository, 0, 128);
			auto address_ethereum = std::find_if(manager_addresses.begin(), manager_addresses.end(), [&](states::witness_account& item) { return item.manager != user1.public_key_hash && item.asset == algorithm::asset::id_of("ETH"); });
			auto address_ripple = std::find_if(owner_addresses.begin(), owner_addresses.end(), [&](states::witness_account& item) { return item.manager != user1.public_key_hash && item.asset == algorithm::asset::id_of("XRP"); });
			auto address_bitcoin = std::find_if(owner_addresses.begin(), owner_addresses.end(), [&](states::witness_account& item) { return item.manager != user1.public_key_hash && item.asset == algorithm::asset::id_of("BTC"); });
			VI_PANIC(address_ethereum != manager_addresses.end(), "ethereum depository address not found");
			VI_PANIC(address_ripple != owner_addresses.end(), "ripple depository address not found");
			VI_PANIC(address_bitcoin != owner_addresses.end(), "bitcoin depository address not found");

			auto token_asset = algorithm::asset::id_of("ETH", "USDT", "0xdAC17F958D2ee523a2206206994597C13D831ec7");
			auto* depository_attestation_ethereum_token = memory::init<transactions::depository_attestation>();
			depository_attestation_ethereum_token->set_asset("ETH");
			depository_attestation_ethereum_token->set_finalized_proof(22946911,
				"0xce2d48c20305ee332c071a671142953af58ca5226fcbcc219cd0b2cc4c6fe34f",
				{ oracle::value_transfer(token_asset, "0xCa0dfDdBb1cBD7B5A08E9173D9bbE5722138d4d5", 100000) },
				{ oracle::value_transfer(token_asset, address_ethereum->addresses.begin()->second, 100000) });
			transactions.push_back(depository_attestation_ethereum_token);

			auto* depository_attestation_ethereum = memory::init<transactions::depository_attestation>();
			depository_attestation_ethereum->set_asset("ETH");
			depository_attestation_ethereum->set_finalized_proof(14977180,
				"0x2bc2c98682f1b8fea2031e8f3f56494cd778da9d042da8439fb698d41bf061ea",
				{ oracle::value_transfer(depository_attestation_ethereum->asset, "0xCa0dfDdBb1cBD7B5A08E9173D9bbE5722138d4d5", 100) },
				{ oracle::value_transfer(depository_attestation_ethereum->asset, address_ethereum->addresses.begin()->second, 100) });
			transactions.push_back(depository_attestation_ethereum);

			auto* depository_attestation_ripple = memory::init<transactions::depository_attestation>();
			depository_attestation_ripple->set_asset("XRP");
			depository_attestation_ripple->set_finalized_proof(88546830,
				"2618D20B801AF96DD060B34228E2594E30AFB7B33E335A8C60199B6CF8B0A69F",
				{ oracle::value_transfer(depository_attestation_ripple->asset, "rUBqz2JiRCT3gYZBnm28y5ME7e5UpSm2ok", 1000) },
				{ oracle::value_transfer(depository_attestation_ripple->asset, address_ripple->addresses.begin()->second, 1000) });
			transactions.push_back(depository_attestation_ripple);

			auto* depository_attestation_bitcoin = memory::init<transactions::depository_attestation>();
			depository_attestation_bitcoin->set_asset("BTC");
			depository_attestation_bitcoin->set_finalized_proof(846982,
				"57638131d9af3033a5e20b753af254e1e8321b2039f16dfd222f6b1117b5c69d",
				{ oracle::value_transfer(depository_attestation_bitcoin->asset, "mmtubFoJvXrBuBUQFf1RrowXUbsiPDYnYS", 1.0) },
				{ oracle::value_transfer(depository_attestation_bitcoin->asset, address_bitcoin->addresses.begin()->second, 1.0) });
			transactions.push_back(depository_attestation_bitcoin);
		}
		static void depository_attestation_registration_partial(vector<uptr<ledger::transaction>>& transactions, vector<account>& users)
		{
			auto& [user1, user1_nonce] = users[0];
			auto context = ledger::transaction_context();
			auto owner_addresses = *context.get_witness_accounts_by_purpose(user1.public_key_hash, states::witness_account::account_type::depository, 0, 128);
			auto address_bitcoin = std::find_if(owner_addresses.begin(), owner_addresses.end(), [](states::witness_account& item) { return item.asset == algorithm::asset::id_of("BTC"); });
			auto address_ethereum = std::find_if(owner_addresses.begin(), owner_addresses.end(), [](states::witness_account& item) { return item.asset == algorithm::asset::id_of("ETH"); });
			VI_PANIC(address_bitcoin != owner_addresses.end(), "bitcoin depository address not found");
			VI_PANIC(address_ethereum != owner_addresses.end(), "ethereum depository address not found");

			auto* depository_attestation_bitcoin = memory::init<transactions::depository_attestation>();
			depository_attestation_bitcoin->set_asset("BTC");
			depository_attestation_bitcoin->set_finalized_proof(846982,
				"57638131d9af3033a5e20b753af254e1e8321b2039f16dfd222f6b1117b5c69d",
				{ oracle::value_transfer(depository_attestation_bitcoin->asset, "mmtubFoJvXrBuBUQFf1RrowXUbsiPDYnYS", 12.0) },
				{ oracle::value_transfer(depository_attestation_bitcoin->asset, address_bitcoin->addresses.begin()->second, 12.0) });
			transactions.push_back(depository_attestation_bitcoin);

			auto token_asset = algorithm::asset::id_of("ETH", "USDT", "0xdAC17F958D2ee523a2206206994597C13D831ec7");
			auto* depository_attestation_ethereum = memory::init<transactions::depository_attestation>();
			depository_attestation_ethereum->set_asset("ETH");
			depository_attestation_ethereum->set_finalized_proof(14977180,
				"0x2bc2c98682f1b8fea2031e8f3f56494cd778da9d042da8439fb698d41bf061ea",
				{ oracle::value_transfer(token_asset, "0xCa0dfDdBb1cBD7B5A08E9173D9bbE5722138d4d5", 1000000) },
				{ oracle::value_transfer(token_asset, address_ethereum->addresses.begin()->second, 1000000) });
			transactions.push_back(depository_attestation_ethereum);
		}
		static void depository_migration(vector<uptr<ledger::transaction>>& transactions, vector<account>& users)
		{
			auto& [user2, user2_nonce] = users[1];
			auto mempool = storages::mempoolstate();
			auto accounts = mempool.get_group_accounts(algorithm::pubkeyhash_t(), 0, 128);
			if (accounts && !accounts->empty())
			{
				auto user2_address = algorithm::pubkeyhash_t(user2.public_key_hash);
				for (auto& account : *accounts)
				{
					if (account.group.find(user2_address) != account.group.end())
					{
						auto* depository_migration_ethereum = memory::init<transactions::depository_migration>();
						depository_migration_ethereum->asset = account.asset;
						depository_migration_ethereum->add_share(account.asset, account.manager, account.owner);
						depository_migration_ethereum->sign(user2.secret_key, user2_nonce++, decimal::zero()).expect("pre-validation failed");
						transactions.push_back(depository_migration_ethereum);
					}
				}
			}
		}
		static void depository_withdrawal_stage_1(vector<uptr<ledger::transaction>>& transactions, vector<account>& users)
		{
			auto& [user1, user1_nonce] = users[0];
			auto& [user2, user2_nonce] = users[1];
			auto* depository_withdrawal_ripple = memory::init<transactions::depository_withdrawal>();
			depository_withdrawal_ripple->set_asset("XRP");
			depository_withdrawal_ripple->set_manager(user2.public_key_hash, user1.public_key_hash);
			depository_withdrawal_ripple->sign(user2.secret_key, user2_nonce++, decimal::zero()).expect("pre-validation failed");
			transactions.push_back(depository_withdrawal_ripple);
		}
		static void depository_withdrawal_stage_2(vector<uptr<ledger::transaction>>& transactions, vector<account>& users)
		{
			auto& [user1, user1_nonce] = users[0];
			auto& [user2, user2_nonce] = users[1];
			auto context = ledger::transaction_context();
			auto* withdrawal_ethereum_token = memory::init<transactions::depository_withdrawal>();
			withdrawal_ethereum_token->set_asset("ETH", "USDT", "0xdAC17F958D2ee523a2206206994597C13D831ec7");
			withdrawal_ethereum_token->set_manager(user2.public_key_hash);
			withdrawal_ethereum_token->set_to("0xCa0dfDdBb1cBD7B5A08E9173D9bbE5722138d4d5", context.get_account_balance(algorithm::asset::id_of("ETH", "USDT", "0xdAC17F958D2ee523a2206206994597C13D831ec7"), user1.public_key_hash).expect("user balance not valid").get_balance());
			withdrawal_ethereum_token->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
			transactions.push_back(withdrawal_ethereum_token);
		}
		static void depository_withdrawal_stage_3(vector<uptr<ledger::transaction>>& transactions, vector<account>& users)
		{
			auto& [user1, user1_nonce] = users[0];
			auto& [user2, user2_nonce] = users[1];
			auto context = ledger::transaction_context();
			auto depository_reward_ethereum = context.get_depository_reward(algorithm::asset::id_of("ETH"), user2.public_key_hash).or_else(states::depository_reward(algorithm::pubkeyhash_t(), 0, nullptr));
			auto* withdrawal_ethereum = memory::init<transactions::depository_withdrawal>();
			withdrawal_ethereum->set_asset("ETH");
			withdrawal_ethereum->set_manager(user2.public_key_hash);
			withdrawal_ethereum->set_to("0xCa0dfDdBb1cBD7B5A08E9173D9bbE5722138d4d5", context.get_account_balance(algorithm::asset::id_of("ETH"), user1.public_key_hash).expect("user balance not valid").get_balance() - depository_reward_ethereum.outgoing_fee);
			withdrawal_ethereum->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
			transactions.push_back(withdrawal_ethereum);

			auto depository_reward_ripple = context.get_depository_reward(algorithm::asset::id_of("XRP"), user1.public_key_hash).or_else(states::depository_reward(algorithm::pubkeyhash_t(), 0, nullptr));
			auto* withdrawal_ripple = memory::init<transactions::depository_withdrawal>();
			withdrawal_ripple->set_asset("XRP");
			withdrawal_ripple->set_manager(user1.public_key_hash);
			withdrawal_ripple->set_to("rUBqz2JiRCT3gYZBnm28y5ME7e5UpSm2ok", context.get_account_balance(algorithm::asset::id_of("XRP"), user1.public_key_hash).expect("user balance not valid").get_balance() - depository_reward_ripple.outgoing_fee);
			withdrawal_ripple->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
			transactions.push_back(withdrawal_ripple);

			auto depository_reward_bitcoin = context.get_depository_reward(algorithm::asset::id_of("BTC"), user2.public_key_hash).or_else(states::depository_reward(algorithm::pubkeyhash_t(), 0, nullptr));
			auto* withdrawal_bitcoin = memory::init<transactions::depository_withdrawal>();
			withdrawal_bitcoin->set_asset("BTC");
			withdrawal_bitcoin->set_manager(user2.public_key_hash);
			withdrawal_bitcoin->set_to("mmtubFoJvXrBuBUQFf1RrowXUbsiPDYnYS", context.get_account_balance(algorithm::asset::id_of("BTC"), user1.public_key_hash).expect("user balance not valid").get_balance() - depository_reward_bitcoin.outgoing_fee);
			withdrawal_bitcoin->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
			transactions.push_back(withdrawal_bitcoin);
		}
		static void depository_withdrawal_stage_4(vector<uptr<ledger::transaction>>& transactions, vector<account>& users)
		{
			auto& [user1, user1_nonce] = users[0];
			auto& [user2, user2_nonce] = users[1];
			auto context = ledger::transaction_context();
			auto depository_reward_ethereum = context.get_depository_reward(algorithm::asset::id_of("ETH"), user2.public_key_hash).or_else(states::depository_reward(algorithm::pubkeyhash_t(), 0, nullptr));
			auto* withdrawal_ethereum = memory::init<transactions::depository_withdrawal>();
			withdrawal_ethereum->set_asset("ETH");
			withdrawal_ethereum->set_manager(user2.public_key_hash);
			withdrawal_ethereum->set_to("0x89a0181659bd280836A2d33F57e3B5Dfa1a823CE", context.get_account_balance(algorithm::asset::id_of("ETH"), user2.public_key_hash).expect("user balance not valid").get_balance() - depository_reward_ethereum.outgoing_fee);
			withdrawal_ethereum->sign(user2.secret_key, user2_nonce++, decimal::zero()).expect("pre-validation failed");
			transactions.push_back(withdrawal_ethereum);

			auto depository_reward_ripple = context.get_depository_reward(algorithm::asset::id_of("XRP"), user1.public_key_hash).or_else(states::depository_reward(algorithm::pubkeyhash_t(), 0, nullptr));
			auto* withdrawal_ripple = memory::init<transactions::depository_withdrawal>();
			withdrawal_ripple->set_asset("XRP");
			withdrawal_ripple->set_manager(user1.public_key_hash);
			withdrawal_ripple->set_to("rJGb4etn9GSwNHYVu7dNMbdiVgzqxaTSUG", context.get_account_balance(algorithm::asset::id_of("XRP"), user2.public_key_hash).expect("user balance not valid").get_balance() - depository_reward_ripple.outgoing_fee);
			withdrawal_ripple->sign(user2.secret_key, user2_nonce++, decimal::zero()).expect("pre-validation failed");
			transactions.push_back(withdrawal_ripple);

			auto depository_reward_bitcoin = context.get_depository_reward(algorithm::asset::id_of("BTC"), user2.public_key_hash).or_else(states::depository_reward(algorithm::pubkeyhash_t(), 0, nullptr));
			auto* withdrawal_bitcoin = memory::init<transactions::depository_withdrawal>();
			withdrawal_bitcoin->set_asset("BTC");
			withdrawal_bitcoin->set_manager(user2.public_key_hash);
			withdrawal_bitcoin->set_to("bcrt1p2w7gkghj7arrjy4c45kh7450458hr8dv9pu9576lx08uuh4je7eqgskm9v", context.get_account_balance(algorithm::asset::id_of("BTC"), user2.public_key_hash).expect("user balance not valid").get_balance() - depository_reward_bitcoin.outgoing_fee);
			withdrawal_bitcoin->sign(user2.secret_key, user2_nonce++, decimal::zero()).expect("pre-validation failed");
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
			value.encode(data1);
			value1.decode(data1);
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
			number.decode((uint8_t*)crypto::random_bytes(32)->data());

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
		algorithm::pubkeyhash_t owner;
		algorithm::hashing::hash160((uint8_t*)"publickeyhash", 13, owner.data);
		uint256_t asset = algorithm::asset::id_of("BTC");
		uint64_t block_number = 1;
		uint64_t block_nonce = 1;

		new_serialization_comparison<oracle::wallet_link>(*data);
		new_serialization_comparison<oracle::coin_utxo>(*data);
		new_serialization_comparison<oracle::computed_transaction>(*data);
		new_serialization_comparison<oracle::prepared_transaction>(*data);
		new_serialization_comparison<oracle::finalized_transaction>(*data);
		new_serialization_comparison<ledger::receipt>(*data);
		new_serialization_comparison<ledger::wallet>(*data);
		new_serialization_comparison<ledger::node>(*data);
		new_serialization_comparison<ledger::block_transaction>(*data);
		new_serialization_comparison<ledger::block_header>(*data);
		new_serialization_comparison<ledger::block>(*data);
		new_serialization_comparison<ledger::block_proof>(*data);
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
		new_serialization_comparison<transactions::upgrade>(*data);
		new_serialization_comparison<transactions::call>(*data);
		new_serialization_comparison<transactions::rollup>(*data);
		new_serialization_comparison<transactions::validator_adjustment>(*data);
		new_serialization_comparison<transactions::depository_account>(*data);
		new_serialization_comparison<transactions::depository_account_finalization>(*data);
		new_serialization_comparison<transactions::depository_withdrawal>(*data);
		new_serialization_comparison<transactions::depository_withdrawal_finalization>(*data);
		new_serialization_comparison<transactions::depository_attestation>(*data);
		new_serialization_comparison<transactions::depository_adjustment>(*data);
		new_serialization_comparison<transactions::depository_migration>(*data);
		new_serialization_comparison<transactions::depository_migration_finalization>(*data);

		auto* term = console::get();
		term->jwrite_line(*data);
	}
	/* prove and verify multiple (nearly) linearly more complex wesolowski vdf signatures */
	static void cryptography_wesolowski()
	{
		auto* term = console::get();
		auto message = "Hello, world!";
		auto data = uptr<schema>(var::set::array());
		auto prove_and_verify = [&](uint64_t ops)
		{
			auto alg = algorithm::wesolowski::parameters();
			alg.ops = ops;

			auto evaluation_time_point = date_time();
			auto proof = algorithm::wesolowski::evaluate(alg, message);

			auto evaluation_time = evaluation_time_point.elapsed();
			auto verification_time_point = date_time();
			bool proven = algorithm::wesolowski::verify(alg, message, proof);

			auto verification_time = verification_time_point.elapsed();
			auto* target = data->push(var::set::object());
			target->set("proof", algorithm::wesolowski::serialize(alg, proof));
			target->set("evaluation_time", var::integer(evaluation_time.milliseconds()));
			target->set("verification_time", var::integer(verification_time.milliseconds()));
			if (!proven)
				term->jwrite_line(*data);
			VI_PANIC(proven, "wesolowki proof is not valid");
		};

		uint64_t baseline = algorithm::wesolowski::parameters().ops;
		prove_and_verify(baseline);
		for (uint64_t i = 3; i < 7; i++)
			prove_and_verify(baseline * (2ll << i));
		term->jwrite_line(*data);
	}
	/* cryptographic signatures */
	static void cryptography_signatures()
	{
		auto* term = console::get();
		string mnemonic = "chimney clerk liberty defense gesture risk disorder switch raven chapter document admit win swing forward please clerk vague online coil material tone sibling intact";
		algorithm::seckey_t secret_key;
		algorithm::pubkey_t public_key;
		algorithm::pubkeyhash_t public_key_hash;
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
		algorithm::hashsig_t message_signature;
		algorithm::pubkey_t recover_public_key;
		algorithm::pubkeyhash_t recover_public_key_hash;
		bool verifies = algorithm::signing::sign(message_hash, secret_key, message_signature) && algorithm::signing::verify(message_hash, public_key, message_signature);
		bool recovers_public_key = algorithm::signing::recover(message_hash, recover_public_key, message_signature);
		bool recovers_public_key_hash = algorithm::signing::recover_hash(message_hash, recover_public_key_hash, message_signature);
		string encoded_message_signature = format::util::encode_0xhex(message_signature.view());
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
		auto message_from_user1 = "Hello, alice!";
		auto message_from_user2 = "Hello, bob!";
		auto ciphertext1 = user1.seal_message(message_from_user1, user2.public_key, 123456).expect("failed to encrypt the message to user 2");
		auto plaintext1 = user2.open_message(ciphertext1).expect("failed to decrypt the message from user 1");
		auto ciphertext2 = user2.seal_message(message_from_user2, user1.public_key, 654321).expect("failed to encrypt the message to user 1");
		auto plaintext2 = user1.open_message(ciphertext2).expect("failed to decrypt the message from user 2");

		uptr<schema> data = var::set::object();
		auto* user1_wallet_data = data->set("user1_wallet", user1.as_schema().reset());
		auto* user1_wallet_message_data = user1_wallet_data->set("message");
		user1_wallet_message_data->set("ciphertext_to_user2_wallet", var::string(format::util::encode_0xhex(ciphertext1)));
		user1_wallet_message_data->set("plaintext_from_user2_wallet", var::string(plaintext2));
		auto* user2_wallet_data = data->set("user2_wallet", user2.as_schema().reset());
		auto* user2_wallet_message_data = user2_wallet_data->set("message");
		user2_wallet_message_data->set("ciphertext_to_user2_wallet", var::string(format::util::encode_0xhex(ciphertext2)));
		user2_wallet_message_data->set("plaintext_from_user2_wallet", var::string(plaintext1));
		term->jwrite_line(*data);
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
		tx.gas_limit = ledger::block::get_transaction_gas_limit();
		tx.set_asset("ETH");
		tx.set_to(users[1].wallet.public_key_hash, decimal("13.539899"));
		VI_PANIC(tx.sign(users[0].wallet.secret_key, users[0].nonce++), "authentication failed");

		auto tx_blob = tx.as_message().data;
		auto tx_body = format::ro_stream(tx_blob);
		auto tx_copy = uptr<ledger::transaction>(transactions::resolver::from_stream(tx_body));
		auto tx_info = tx.as_schema();
		algorithm::pubkeyhash_t recover_public_key_hash;
		tx_info->set("raw_data", var::string(format::util::encode_0xhex(tx_blob)));

		auto stream = tx.as_message();
		auto reader = stream.ro();
		format::variables vars;
		format::variables_util::deserialize_flat_from(reader, &vars);
		tx_info->set("var_data", format::variables_util::serialize(vars));
		tx_info->set("asset_id", algorithm::asset::serialize(algorithm::asset::id_of("ETH", "USDT", "0xdAC17F958D2ee523a2206206994597C13D831ec7")));
		term->jwrite_line(*tx_info);

		VI_PANIC(tx.recover_hash(recover_public_key_hash) && wallet.public_key_hash == recover_public_key_hash, "failed to recover the public key hash from signature");
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
		vector<uint256_t> hashset;
		hashset.reserve(hashes + 1);
		hashset.push_back(prev);
		for (size_t i = 0; i < hashes; i++)
		{
			uint8_t hash[32];
			next.encode(hash);

			hashset.push_back(next);
			next = algorithm::hashing::hash256i(std::string_view((char*)hash, sizeof(hash)));
		}

		auto tree = algorithm::merkle_tree::from(std::move(hashset));
		uint256_t target = tree.nodes[math64u::random(1, hashes + 1)];
		term->fwrite_line("merkle tree (nodes = %i, target = %s):", (int)tree.nodes.size(), algorithm::encoding::encode_0xhex256(target).c_str());
		for (size_t i = 0; i < tree.nodes.size(); i++)
			term->write_line("  " + algorithm::encoding::encode_0xhex256(tree.nodes[i]));

		auto path = tree.path(target);
		auto proposed_root = path.root(target);
		auto actual_root = tree.root();
		path.branch.insert(path.branch.begin(), target);
		path.branch.push_back(proposed_root);

		term->fwrite_line("merkle tree path (index in tree = %i, nodes = %i):", (int)path.index, (int)path.branch.size());
		for (size_t i = 0; i < path.branch.size(); i++)
			term->write_line("  " + algorithm::encoding::encode_0xhex256(path.branch[i]));

		term->fwrite_line("merkle tree (complexity = %i, nodes = %i, verification = %s):", (int)tree.size(), (int)tree.nodes.size(), proposed_root == actual_root ? "passed" : "failed");
		for (size_t i = 0; i < tree.nodes.size(); i++)
		{
			auto it = std::find(path.branch.begin(), path.branch.end(), tree.nodes[i]);
			if (it != path.branch.end())
			{
				size_t depth = it - path.branch.begin() + 1;
				term->write_line("  " + string(depth, '>') + string(1 + path.branch.size() - depth, ' ') + algorithm::encoding::encode_0xhex256(tree.nodes[i]));
			}
			else
				term->write_line("  " + string(1 + path.branch.size(), ' ') + algorithm::encoding::encode_0xhex256(tree.nodes[i]));
		}
		VI_PANIC(proposed_root == actual_root, "cryptographic error");
	}
	/* oracle wallets cryptography */
	static void cryptography_multichain_wallet()
	{
		auto* term = console::get();
		auto* server = oracle::server_node::get();
		auto user = ledger::wallet::from_seed("0000000");
		for (auto& asset : server->get_assets())
		{
			auto wallet = *server->compute_wallet(asset, 123456);
			auto info = wallet.as_schema();
			info->set("asset", algorithm::asset::serialize(asset));
			term->jwrite_line(*info);
		}
	}
	/* multi-party wallet keypair and signature generation */
	static void cryptography_multichain_mpc()
	{
		auto* term = console::get();
		vector<participant> participants;
		participants.resize(protocol::now().policy.participation_std_per_account);

		for (auto& [alg, alg_name] :
			{
				std::make_pair(algorithm::composition::type::ed25519, std::string_view("ed25519")),
				std::make_pair(algorithm::composition::type::ed25519_clsag, std::string_view("ed25519_clsag")),
				std::make_pair(algorithm::composition::type::secp256k1, std::string_view("secp256k1")),
				std::make_pair(algorithm::composition::type::secp256k1_schnorr, std::string_view("secp256k1_schnorr"))
			})
		{
			uint64_t mpc_secret_state_time = 0;
			uint64_t mpc_public_state_time = 0;
			size_t mpc_secret_state_bandwidth = 0;
			size_t mpc_public_state_bandwidth = 0;
			auto mpc_data = uptr(var::set::object());
			auto mpc_secret_state = algorithm::composition::make_secret_state(alg).expect("failed to make the secret state");
			auto mpc_public_state = algorithm::composition::make_public_state(alg).expect("failed to make the public state");
			for (size_t i = 0; i < participants.size(); i++)
			{
				auto& share = participants[i];
				share.seed = algorithm::hashing::hash256i("seed" + to_string(i));
				share.keypair = algorithm::composition::derive_keypair(alg, share.seed).expect("failed to derive a keypair share");
				{
					auto time = date_time();
					format::wo_stream message;
					algorithm::composition::store_secret_state(alg, *mpc_secret_state, &message).expect("failed to store the secret state");

					auto reader = message.ro();
					mpc_secret_state = algorithm::composition::load_secret_state(reader).expect("failed to load the secret state");
					mpc_secret_state->derive_from_key(share.keypair.secret_key).expect("failed to aggregate the secret state");

					format::wo_stream updated_message;
					algorithm::composition::store_secret_state(alg, *mpc_secret_state, &updated_message).expect("failed to store the secret state");
					mpc_secret_state_bandwidth += message.data.size() + updated_message.data.size();
					mpc_secret_state_time += date_time().nanoseconds() - time.nanoseconds();
				}
				{
					auto time = date_time();
					format::wo_stream message;
					algorithm::composition::store_public_state(alg, *mpc_public_state, &message).expect("failed to store the public state");

					auto reader = message.ro();
					mpc_public_state = algorithm::composition::load_public_state(reader).expect("failed to load the public state");
					mpc_public_state->derive_from_key(share.keypair.secret_key).expect("failed to aggregate the public state");

					format::wo_stream updated_message;
					algorithm::composition::store_public_state(alg, *mpc_public_state, &updated_message).expect("failed to store the public state");
					mpc_public_state_bandwidth += message.data.size() + updated_message.data.size();
					mpc_public_state_time += date_time().nanoseconds() - time.nanoseconds();
				}

				auto participant_data = mpc_data->set("participant" + to_string(i + 1), var::set::object());
				participant_data->set("seed", var::string(algorithm::encoding::encode_0xhex256(share.seed)));
				participant_data->set("secret_key", var::string(format::util::encode_0xhex(std::string_view((char*)share.keypair.secret_key.data(), share.keypair.secret_key.size()))));
				participant_data->set("public_key", var::string(format::util::encode_0xhex(std::string_view((char*)share.keypair.public_key.data(), share.keypair.public_key.size()))));
			}

			uint8_t message_hash[32];
			std::string_view message = "Hello, World!";
			algorithm::composition::cseckey_t mpc_secret_key;
			algorithm::composition::cpubkey_t mpc_public_key;
			algorithm::hashing::hash256((uint8_t*)message.data(), message.size(), message_hash);
			mpc_secret_state->finalize(&mpc_secret_key).expect("failed to finalize the secret state");
			mpc_public_state->finalize(&mpc_public_key).expect("failed to finalize the public state");

			uint64_t mpc_signature_state_time = 0;
			size_t mpc_signature_steps = 0;
			size_t mpc_signature_state_bandwidth = 0;
			auto mpc_chosen_phase_participant = participants.begin() + (size_t)(crypto::random() % (uint64_t)participants.size());
			auto mpc_phase_participants = vector<participant>();
			auto mpc_signature_timeline = vector<string>();
			auto mpc_signature_state = algorithm::composition::make_signature_state(alg, mpc_public_key, message_hash, sizeof(message_hash), (uint16_t)participants.size()).expect("failed to make the signature state");
			while (true)
			{
				auto time = date_time();
				auto next = mpc_phase_participants.end();
				switch (mpc_signature_state->next_phase())
				{
					case algorithm::composition::phase::any_input_after_reset:
						mpc_phase_participants = participants;
						next = mpc_phase_participants.begin();
						next = mpc_phase_participants.size() > 1 && next->seed == mpc_chosen_phase_participant->seed ? next + 1 : next;
						mpc_signature_timeline.push_back("next_round");
						mpc_signature_timeline.push_back("use_participant" + to_string(1 + std::distance(participants.begin(), std::find_if(participants.begin(), participants.end(), [&](const participant& item) { return item.seed == next->seed; }))));
						break;
					case algorithm::composition::phase::any_input:
						next = mpc_phase_participants.begin();
						next = mpc_phase_participants.size() > 1 && next->seed == mpc_chosen_phase_participant->seed ? next + 1 : next;
						mpc_signature_timeline.push_back("use_participant" + to_string(1 + std::distance(participants.begin(), std::find_if(participants.begin(), participants.end(), [&](const participant& item) { return item.seed == next->seed; }))));
						break;
					case algorithm::composition::phase::chosen_input_after_reset:
						mpc_phase_participants = participants;
						next = std::find_if(mpc_phase_participants.begin(), mpc_phase_participants.end(), [&](const participant& item) { return item.seed == mpc_chosen_phase_participant->seed; });
						mpc_signature_timeline.push_back("next_round");
						mpc_signature_timeline.push_back("reuse_participant" + to_string(1 + std::distance(participants.begin(), std::find_if(participants.begin(), participants.end(), [&](const participant& item) { return item.seed == next->seed; }))));
						break;
					case algorithm::composition::phase::chosen_input:
						next = std::find_if(mpc_phase_participants.begin(), mpc_phase_participants.end(), [&](const participant& item) { return item.seed == mpc_chosen_phase_participant->seed; });
						mpc_signature_timeline.push_back("reuse_participant" + to_string(1 + std::distance(participants.begin(), std::find_if(participants.begin(), participants.end(), [&](const participant& item) { return item.seed == next->seed; }))));
						break;
					case algorithm::composition::phase::finalized:
						mpc_signature_timeline.push_back("final_round");
						break;
					default:
						VI_PANIC(false, "invalid phase");
						break;
				}
				if (next == mpc_phase_participants.end())
					break;

				format::wo_stream message;
				algorithm::composition::store_signature_state(alg, *mpc_signature_state, &message).expect("failed to store the signature state");

				auto reader = message.ro();
				mpc_signature_state = algorithm::composition::load_signature_state(reader).expect("failed to load the signature state");
				mpc_signature_state->aggregate(next->keypair.secret_key).expect("failed to aggregate the signature state");
				mpc_phase_participants.erase(next);

				format::wo_stream updated_message;
				algorithm::composition::store_signature_state(alg, *mpc_signature_state, &updated_message).expect("failed to store the signature state");
				mpc_signature_state_bandwidth += message.data.size() + updated_message.data.size();
				mpc_signature_state_time += date_time().nanoseconds() - time.nanoseconds();
				++mpc_signature_steps;
			}

			algorithm::composition::chashsig_t mpc_signature;
			mpc_signature_state->finalize(&mpc_signature).expect("failed to finalize the signature state");

			auto* secret_aggregation_data = mpc_data->set("secret_aggregation", var::set::object());
			secret_aggregation_data->set("secret_key", var::string(format::util::encode_0xhex(std::string_view((char*)mpc_secret_key.data(), mpc_secret_key.size()))));
			secret_aggregation_data->set("network_bytes_required", var::integer(mpc_secret_state_bandwidth));
			secret_aggregation_data->set("network_communications", var::integer(participants.size() * 2));
			secret_aggregation_data->set("step_time_ns", var::integer(mpc_secret_state_time / participants.size()));
			secret_aggregation_data->set("total_time_ms", var::integer(mpc_secret_state_time / 1'000'000));

			auto* public_aggregation_data = mpc_data->set("public_aggregation", var::set::object());
			public_aggregation_data->set("public_key", var::string(format::util::encode_0xhex(std::string_view((char*)mpc_public_key.data(), mpc_public_key.size()))));
			public_aggregation_data->set("network_bytes_required", var::integer(mpc_public_state_bandwidth));
			public_aggregation_data->set("network_communications", var::integer(participants.size() * 2));
			public_aggregation_data->set("step_time_ns", var::integer(mpc_public_state_time / participants.size()));
			public_aggregation_data->set("total_time_ms", var::integer(mpc_public_state_time / 1'000'000));

			auto* signature_aggregation_data = mpc_data->set("signature_aggregation", var::set::object());
			auto* signature_aggregation_timeline_data = signature_aggregation_data->set("timeline", var::set::array());
			signature_aggregation_data->set("signature", var::string(format::util::encode_0xhex(std::string_view((char*)mpc_signature.data(), mpc_signature.size()))));
			signature_aggregation_data->set("network_bytes_required", var::integer(mpc_signature_state_bandwidth));
			signature_aggregation_data->set("network_communications", var::integer(mpc_signature_steps * 2));
			signature_aggregation_data->set("step_time_ns", var::integer(mpc_signature_steps > 0 ? mpc_signature_state_time / mpc_signature_steps : 0));
			signature_aggregation_data->set("total_time_ms", var::integer(mpc_signature_state_time / 1'000'000));
			for (auto& item : mpc_signature_timeline)
				signature_aggregation_timeline_data->push(var::string(item));

			mpc_data->set("message", var::string(message));
			mpc_data->set("message_hash", var::string(format::util::encode_0xhex(std::string_view((char*)message_hash, sizeof(message_hash)))));
			mpc_data->set("algorithm", var::string(alg_name));
			mpc_data->set("participants", var::integer(participants.size()));
			term->jwrite_line(*mpc_data);
		}
	}
	/* oracle transaction generation test */
	static void cryptography_multichain_transaction()
	{
		auto* server = oracle::server_node::get();
		auto* term = console::get();
		auto seed = uint256_t(123456);
		auto user = ledger::wallet::from_seed(seed.to_string());
		auto create_wallet = [&](const algorithm::asset_id& asset) -> oracle::computed_wallet
		{
			auto wallet = *server->compute_wallet(asset, seed);
			for (auto& encoded_address : wallet.encoded_addresses)
				server->enable_link(asset, oracle::wallet_link(user.public_key_hash, wallet.encoded_public_key, encoded_address.second)).expect("link activation error");
			return wallet;
		};
		auto validate_transaction = [&](const algorithm::asset_id& asset, const oracle::computed_wallet& wallet, oracle::prepared_transaction& prepared, const std::string_view& environment, const std::string_view& expected_calldata)
		{
			for (auto& input : prepared.inputs)
			{
				auto state = algorithm::composition::make_signature_state(input.alg, input.public_key, input.message.data(), input.message.size(), 1).expect("signature state initialization error");
				while (state->next_phase() != algorithm::composition::phase::finalized)
					state->aggregate(wallet.secret_key).expect("signature aggregation error");
				state->finalize(&input.signature);
			}

			oracle::finalized_transaction finalized = server->finalize_transaction(asset, std::move(prepared)).expect("prepared transaction finalization error");
			VI_PANIC(finalized.calldata == expected_calldata, "resulting calldata differs from expected calldata");
			term->fwrite_line("%s (%.*s) = %s", algorithm::asset::handle_of(asset).c_str(), (int)environment.size(), environment.data(), finalized.calldata.c_str());
		};
		use_clean_state([&]()
		{
			auto asset = algorithm::asset::id_of("BTC");
			auto state = storages::oraclestate(asset);
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
			oracle::coin_utxo input_p2pkh;
			input_p2pkh.link = oracle::wallet_link(user.public_key_hash, wallet.encoded_public_key, wallet.encoded_addresses[3]);
			input_p2pkh.transaction_id = "382940bfc9a1fe1f09a3fb8e1fda1b25b90dc2019ff5973b1d9d616e15b29840";
			input_p2pkh.index = 1;
			input_p2pkh.value = 0.1;

			auto input_p2sh_hash = codec::hex_decode("0xc4e23865424498b4d90c57dda4bea4718e1e6ed669cc00796afd864ac6de3606");
			oracle::coin_utxo input_p2sh;
			input_p2sh.link = oracle::wallet_link(user.public_key_hash, wallet.encoded_public_key, wallet.encoded_addresses[2]);
			input_p2sh.transaction_id = "3d7c1f8e03a73821517d2f0220fe3ecf82c2f55b94b724e5d5298c87070802a0";
			input_p2sh.value = 0.1;

			auto input_p2wpkh_hash_1 = codec::hex_decode("0xe79739ac82960be8bedb5175203bd65880b0c45c5c0286d54b5bc6eb4bac3898");
			oracle::coin_utxo input_p2wpkh_1;
			input_p2wpkh_1.link = oracle::wallet_link(user.public_key_hash, wallet.encoded_public_key, wallet.encoded_addresses[6]);
			input_p2wpkh_1.transaction_id = "5594c04289179bff0f434e5349fafbaa4d43da403b9dc7a637f5afe035b99729";
			input_p2wpkh_1.value = 0.1;

			auto input_p2tr_public_key = compositions::secp256k1_public_state::point_t(wallet.public_key);
			auto input_p2tr_tweak = compositions::secp256k1_secret_state::scalar_t(codec::hex_decode("0x04c32a8b5fae170a7a0d28332a663b96f43d24ed4c9db30dfdd9d9d053d3d3e6"));
			auto input_p2tr_tweaked_public_key = compositions::secp256k1_schnorr_signature_state::to_tweaked_public_key(input_p2tr_public_key, input_p2tr_tweak).expect("failed to tweak a public key");
			auto input_p2tr_hash = codec::hex_decode("0x50cc324f902032625ba70fdfee889032a7ff4de1c7732dc3982b72c1ba2df8b5");
			oracle::coin_utxo input_p2tr;
			input_p2tr.link = oracle::wallet_link(user.public_key_hash, wallet.encoded_public_key, wallet.encoded_addresses[4]);
			input_p2tr.transaction_id = "988fcb7035c0f51688ddcfaf92ec8fdd0e9bda8b53aa3403bf096611147fb325";
			input_p2tr.value = 0.1;

			auto input_p2wpkh_hash_2 = codec::hex_decode("0x16a41f749d25f7ebae96aabd62207c2189ac3623b2ddee4560213a3563f81042");
			oracle::coin_utxo input_p2wpkh_2;
			input_p2wpkh_2.link = oracle::wallet_link(user.public_key_hash, wallet.encoded_public_key, wallet.encoded_addresses[6]);
			input_p2wpkh_2.transaction_id = "9b7a67a6a46f48f896c1de89d479d9d1f5b284809065671ff931c800e1041530";
			input_p2wpkh_2.value = 0.1;

			auto input_p2wsh_hash = codec::hex_decode("0x40cfd352d152929ada057d28c0e18f781a8b9ddb24df1b6381b0738c8f0ccbb9");
			oracle::coin_utxo input_p2wsh;
			input_p2wsh.link = oracle::wallet_link(user.public_key_hash, wallet.encoded_public_key, wallet.encoded_addresses[5]);
			input_p2wsh.transaction_id = "ccc7949d20241f04362c42e20125c83096a617b906e1d8123d1b8b08740c6025";
			input_p2wsh.index = 1;
			input_p2wsh.value = decimal("0.1001");

			auto input_p2pk_hash = codec::hex_decode("0xe665fd68a288da956f73810db79647a59dbbd6dafb0891f97364a0dfff520b2e");
			oracle::coin_utxo input_p2pk;
			input_p2pk.link = oracle::wallet_link(user.public_key_hash, wallet.encoded_public_key, wallet.encoded_addresses[1]);
			input_p2pk.transaction_id = "f0b0d2386cd578677df2380361410008d260fc827282904e54bdcb9e1d8cf62f";
			input_p2pk.index = 0;
			input_p2pk.value = decimal("0.0999");

			oracle::coin_utxo output_p2wpkh;
			output_p2wpkh.link = oracle::wallet_link::from_address("bcrt1q9ls8q57rsktvxn6krgjktd6jyukfpenyvd2sa3");
			output_p2wpkh.value = 0.65;

			oracle::coin_utxo output_p2pkh;
			output_p2pkh.link = input_p2pkh.link;
			output_p2pkh.index = 1;
			output_p2pkh.value = decimal("0.0499");

			oracle::prepared_transaction prepared;
			prepared.requires_input(algorithm::composition::type::secp256k1, wallet.public_key, (uint8_t*)input_p2pkh_hash.data(), input_p2pkh_hash.size(), std::move(input_p2pkh));
			prepared.requires_input(algorithm::composition::type::secp256k1, wallet.public_key, (uint8_t*)input_p2sh_hash.data(), input_p2sh_hash.size(), std::move(input_p2sh));
			prepared.requires_input(algorithm::composition::type::secp256k1, wallet.public_key, (uint8_t*)input_p2wpkh_hash_1.data(), input_p2wpkh_hash_1.size(), std::move(input_p2wpkh_1));
			prepared.requires_input(algorithm::composition::type::secp256k1_schnorr, input_p2tr_tweaked_public_key, (uint8_t*)input_p2tr_hash.data(), input_p2tr_hash.size(), std::move(input_p2tr));
			prepared.requires_input(algorithm::composition::type::secp256k1, wallet.public_key, (uint8_t*)input_p2wpkh_hash_2.data(), input_p2wpkh_hash_2.size(), std::move(input_p2wpkh_2));
			prepared.requires_input(algorithm::composition::type::secp256k1, wallet.public_key, (uint8_t*)input_p2wsh_hash.data(), input_p2wsh_hash.size(), std::move(input_p2wsh));
			prepared.requires_input(algorithm::composition::type::secp256k1, wallet.public_key, (uint8_t*)input_p2pk_hash.data(), input_p2pk_hash.size(), std::move(input_p2pk));
			prepared.requires_output(std::move(output_p2wpkh));
			prepared.requires_output(std::move(output_p2pkh));
			validate_transaction(asset, wallet, prepared, "p2pk, p2pkh, p2sh, p2wpkh, p2wsh, p2tr", "010000000001074098b2156e619d1d3b97f59f01c20db9251bda1f8efba3091ffea1c9bf402938010000006a47304402204e33cc4508a8a3b80718856850d6d44c258cd8cb0085471feeee870c0174eedd02201749240ef5961c36956209ab4c4928adfa68555dacefa684383f8f88680897a5012102986445ccfd323143f392b66b8cfc056df90ebdc110573e3395ee670d5043f23affffffffa0020807878c29d5e524b7945bf5c282cf3efe20022f7d512138a7038e1f7c3d000000001716001418e254169de2c06bbe881f971b312084bf7d7e1cffffffff2997b935e0aff537a6c79d3b40da434daafbfa49534e430fff9b178942c094550000000000ffffffff25b37f14116609bf0334aa538bda9b0edd8fec92afcfdd8816f5c03570cb8f980000000000ffffffff301504e100c831f91f6765908084b2f5d1d979d489dec196f8486fa4a6677a9b0000000000ffffffff25600c74088b1b3d12d8e106b917a69630c82501e2422c36041f24209d94c7cc0100000000ffffffff2ff68c1d9ecbbd544e90827282fc60d2080041610338f27d6778d56c38d2b0f00000000049483045022100a91590f6154e6116afa393a4c71cb337b8a9bd1a83dc2305bc5718dcde9c1b45022001a60381a18b6b224c71193817a1d76b78d00334bbd651ec3e17e7fe7673a06401ffffffff0240d2df03000000001600142fe07053c38596c34f561a2565b752272c90e66430244c00000000001976a91418e254169de2c06bbe881f971b312084bf7d7e1c88ac0002483045022100b51bf896785af284690485b6b9fff90ee000032b7c135ec4a3b2cf1ee6ae9b5202203fa9aabd0ea22482e5f955fa0eb8e696d50fe2999793857f13be39ddc1871a89012102986445ccfd323143f392b66b8cfc056df90ebdc110573e3395ee670d5043f23a02483045022100b5ffeb7bb826eb7f743f32e7026d20cba8403a46de21ba3cc92bbcf228e8de6e02202fa447539d338f884ece7c4c181b8b590a846f3f9469721304ed0cbc407ee672012102986445ccfd323143f392b66b8cfc056df90ebdc110573e3395ee670d5043f23a014026371d3a2baaf32f56cc0e8bb0f940d243facb694ee877b34540100c5498a2ef6698effdc811e516e62ba20f187ebdc25e30208b787eac053875292088c09a56024730440220381691df2e8d7c5afdd7f71287351ec3a551a2d7a0b1afdaaa3afe42112ca0c90220408dc12aa8351c3a6808019db1b05afa4ca0798578582c259190cdcf756685b7012102986445ccfd323143f392b66b8cfc056df90ebdc110573e3395ee670d5043f23a03483045022100aefdc4da0db0934e6ba5bcd9b6f624c995c432420e237047be28aa4656eea5c0022054fd1563c3538bbec6132b8d8eb21ea49df81f059d50b1f01f3cb0fc18981715012102986445ccfd323143f392b66b8cfc056df90ebdc110573e3395ee670d5043f23a1976a91418e254169de2c06bbe881f971b312084bf7d7e1c88ac0000000000");
		});
		use_clean_state([&]()
		{
			auto asset = algorithm::asset::id_of("BCH");
			auto state = storages::oraclestate(asset);
			auto wallet = create_wallet(asset);

			auto input_p2pkh_hash = codec::hex_decode("0x06da9b13756115c79c0361a083d340c75ced09ddfec9a530601d73a0021ba6a5");
			oracle::coin_utxo input_p2pkh;
			input_p2pkh.link = oracle::wallet_link(user.public_key_hash, wallet.encoded_public_key, wallet.encoded_addresses[1]);
			input_p2pkh.transaction_id = "8d4157a810c52d392c871867fcb5e5375df7102857eea5d770781737c67e5ed4";
			input_p2pkh.index = 0;
			input_p2pkh.value = 0.1;

			oracle::coin_utxo output_p2pkh;
			output_p2pkh.link = oracle::wallet_link::from_address("bchreg:qzpz97kqvz9jj6tdr6wxdt7zyh7vtm8nwyy4ajnft4");
			output_p2pkh.index = 0;
			output_p2pkh.value = decimal("0.099");

			oracle::prepared_transaction prepared;
			prepared.requires_input(algorithm::composition::type::secp256k1, wallet.public_key, (uint8_t*)input_p2pkh_hash.data(), input_p2pkh_hash.size(), std::move(input_p2pkh));
			prepared.requires_output(std::move(output_p2pkh));
			validate_transaction(asset, wallet, prepared, "p2pkh", "0100000001d45e7ec637177870d7a5ee572810f75d37e5b5fc6718872c392dc510a857418d000000006a47304402207fe230c834aebaa9c865ab75ff1b95efd40b1bce71c53b7f16ba09a6b99b4f0c022057fbc1f185f135ab29da2f701cecb22e53cc93e373edb429ac54a179b1c3e31f412102986445ccfd323143f392b66b8cfc056df90ebdc110573e3395ee670d5043f23affffffff01e00f9700000000001976a9148222fac0608b29696d1e9c66afc225fcc5ecf37188ac00000000");
		});
		use_clean_state([&]()
		{
			auto asset = algorithm::asset::id_of("ETH");
			auto state = storages::oraclestate(asset);
			auto wallet = create_wallet(asset);

			auto signable_link = oracle::wallet_link(user.public_key_hash, wallet.encoded_public_key, wallet.encoded_addresses.begin()->second);
			auto signable_message = codec::hex_decode("0x9b9f8b794b538c722eb56fd2b6a238bd2e0af795c6b0b2e4aef6dcb3fafbda38");
			oracle::prepared_transaction prepared;
			prepared.requires_account_input(algorithm::composition::type::secp256k1, std::move(signable_link), wallet.public_key, (uint8_t*)signable_message.data(), signable_message.size(), { { asset, decimal("0.01") } });
			prepared.requires_account_output("0x92F9727Da59BE92F945a72F6eD9b5De8783e09D3", { { asset, 0.01 } });
			prepared.requires_abi(format::variable(true));
			prepared.requires_abi(format::variable(string()));
			prepared.requires_abi(format::variable(decimal("1000000000000000000")));
			prepared.requires_abi(format::variable((uint32_t)2));
			prepared.requires_abi(format::variable((uint32_t)46860));
			prepared.requires_abi(format::variable((uint32_t)0));
			prepared.requires_abi(format::variable((uint32_t)1000000000));
			prepared.requires_abi(format::variable((uint32_t)21000));
			validate_transaction(asset, wallet, prepared, "eip155, transfer", "0xf86d02843b9aca008252089492f9727da59be92f945a72f6ed9b5de8783e09d3872373d8fe36b0008083016e3ba030e80e351dff9a28bb0cc85db19c1a07cde45adb03d59acb6ce3690feba81dcda01d4b6924ced684cddce0c90a93664790437ce41b6b5271b1ad12081ca14f1f00");

			auto token_asset = algorithm::asset::id_of("ETH", "TT", "0xDcbcBF00604Bad29E53C60ac1151866Fa0CC2920");
			signable_link = oracle::wallet_link(user.public_key_hash, wallet.encoded_public_key, wallet.encoded_addresses.begin()->second);
			signable_message = codec::hex_decode("0x430483f3812b96bfe179cd21fb18580c5ba0919c1e25090d9fd740bb238d7bdf");
			prepared = oracle::prepared_transaction();
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
			validate_transaction(asset, wallet, prepared, "eip155, erc20 transfer", "0xf8ab01843b9aca0082c64694dcbcbf00604bad29e53c60ac1151866fa0cc292080b844a9059cbb000000000000000000000000ba119f26a40145b463dfcae2590b68a057e81d3d00000000000000000000000000000000000000000000001b4486fafde57c000083016e3ba0ed04c78bd290e92362d6909eeec76449896155669823ab22de90946298b0c7d0a03848a83fd7176228568a3ee5420ff000e835c8545c3df103585e1fe432c8add5");

			signable_link = oracle::wallet_link(user.public_key_hash, wallet.encoded_public_key, wallet.encoded_addresses.begin()->second);
			signable_message = codec::hex_decode("0xb40bbe4bd0c1f8eb575f079d2d115558712174da9645453a9a76111946117275");
			prepared = oracle::prepared_transaction();
			prepared.requires_account_input(algorithm::composition::type::secp256k1, std::move(signable_link), wallet.public_key, (uint8_t*)signable_message.data(), signable_message.size(), { { asset, decimal("0.1") } });
			prepared.requires_account_output("0x92F9727Da59BE92F945a72F6eD9b5De8783e09D3", { { asset, 0.1 } });
			prepared.requires_abi(format::variable(false));
			prepared.requires_abi(format::variable(string()));
			prepared.requires_abi(format::variable(decimal("1000000000000000000")));
			prepared.requires_abi(format::variable((uint32_t)2));
			prepared.requires_abi(format::variable((uint32_t)46860));
			prepared.requires_abi(format::variable((uint32_t)0));
			prepared.requires_abi(format::variable((uint32_t)1000000000));
			prepared.requires_abi(format::variable((uint32_t)21000));
			validate_transaction(asset, wallet, prepared, "eip1559, transfer", "0x02f87082b70c0280843b9aca008252089492f9727da59be92f945a72f6ed9b5de8783e09d3880163325eebffb00080c080a00fc83f501491b3a2da3804ed2e3d2d8c235b99fc3ef81f8cbe76895603606879a00bf2f9e4d887600be3f1f7f03a10e23d94dc72d1827f0776f5646dbff0b85b0c");

			signable_link = oracle::wallet_link(user.public_key_hash, wallet.encoded_public_key, wallet.encoded_addresses.begin()->second);
			signable_message = codec::hex_decode("0x2785859c7efc21a7f372d723ff833101a8ec5f37003b698fd5afa0e54dec93f4");
			prepared = oracle::prepared_transaction();
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
			validate_transaction(asset, wallet, prepared, "eip1559, erc20 transfer", "0x02f8ad82b70c0280843b9aca0082c64694dcbcbf00604bad29e53c60ac1151866fa0cc292080b844a9059cbb000000000000000000000000ba119f26a40145b463dfcae2590b68a057e81d3d00000000000000000000000000000000000000000000001b4486fafde57c0000c080a0bc3587e4bd45709e7987b26a5c5de16a24d73064e4936a03fc580195e261f79ea02cd70c6a720b24bac786b25267369c486cc4c8da8ab12b9c4dabe183eab12313");
		});
		use_clean_state([&]()
		{
			auto asset = algorithm::asset::id_of("XRP");
			auto state = storages::oraclestate(asset);
			auto wallet = create_wallet(asset);

			auto signable_link = oracle::wallet_link(user.public_key_hash, wallet.encoded_public_key, wallet.encoded_addresses.begin()->second);
			auto signable_message = codec::hex_decode("0x53545800120000220000000024006115562e00000000201b006117fb614000000002b709a468400000000000000c7321ed2a994a958414a9dac047fd32001847954f89f464433cb04266fde37d6aff15448114c7f083a28227b588c13becf3f353e06d2e4f2fee8314f667b0ca50cc7709a220b0561b85e53a48461fa8");
			oracle::prepared_transaction prepared;
			prepared.requires_account_input(algorithm::composition::type::ed25519, std::move(signable_link), wallet.public_key, (uint8_t*)signable_message.data(), signable_message.size(), { { asset, decimal("45.550012") } });
			prepared.requires_account_output("rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe", { { asset, decimal("45.55") } });
			prepared.requires_abi(format::variable(string()));
			prepared.requires_abi(format::variable((uint32_t)6362454));
			prepared.requires_abi(format::variable((uint32_t)6363131));
			prepared.requires_abi(format::variable((uint32_t)12));
			validate_transaction(asset, wallet, prepared, "payment", "120000220000000024006115562E00000000201B006117FB614000000002B709A468400000000000000C7321ED2A994A958414A9DAC047FD32001847954F89F464433CB04266FDE37D6AFF154474405F64465D11E10D41007C2FFBB7921C3AF2F530020BF48A03792B0DAF51E3483324B06E66208376BDACD14EC076FF004256C8457713ADE184CA32B652421ABC0A8114C7F083A28227B588C13BECF3F353E06D2E4F2FEE8314F667B0CA50CC7709A220B0561B85E53A48461FA8");
		});
		use_clean_state([&]()
		{
			auto asset = algorithm::asset::id_of("XLM");
			auto state = storages::oraclestate(asset);
			auto wallet = create_wallet(asset);

			auto signable_link = oracle::wallet_link(user.public_key_hash, wallet.encoded_public_key, wallet.encoded_addresses.begin()->second);
			auto signable_message = codec::hex_decode("0x1a6e7daa8fbd8aab869ebeafc8650d911a948d6e8166aec4fcec5490e359f81d");
			oracle::prepared_transaction prepared;
			prepared.requires_account_input(algorithm::composition::type::ed25519, std::move(signable_link), wallet.public_key, (uint8_t*)signable_message.data(), signable_message.size(), { { asset, decimal("2200.00001") } });
			prepared.requires_account_output("GAIH3ULLFQ4DGSECF2AR555KZ4KNDGEKN4AFI4SU2M7B43MGK3QJZNSR", { { asset, decimal("2200") } });
			prepared.requires_abi(format::variable((uint64_t)1561327986278402));
			prepared.requires_abi(format::variable((uint32_t)0));
			prepared.requires_abi(format::variable((uint32_t)1));
			prepared.requires_abi(format::variable(false));
			prepared.requires_abi(format::variable(string()));
			prepared.requires_abi(format::variable(string()));
			prepared.requires_abi(format::variable((uint32_t)0));
			validate_transaction(asset, wallet, prepared, "payment", "AAAAACqZSpWEFKnawEf9MgAYR5VPifRkQzywQmb9431q/xVEAAAAZAAFjAUAAAACAAAAAAAAAAAAAAABAAAAAAAAAAEAAAAAEH3Rayw4M0iCLoEe96rPFNGYim8AVHJU0z4ebYZW4JwAAAAAAAAABR9NXAAAAAAAAAAAAWr/FUQAAABAHsqVejb7HruH0aV6UzYwvWywdrywphFRCPxe//qGobXsVcgX3LzBl4uARxrUFwYqDSRHahYetDvO79gcvUIhBQ==");

			signable_link = oracle::wallet_link(user.public_key_hash, wallet.encoded_public_key, wallet.encoded_addresses.begin()->second);
			signable_message = codec::hex_decode("0xc23a0791a11ebefd653684792b4001e294440ce67979fb7a0dc2915ca4818e22");
			prepared = oracle::prepared_transaction();
			prepared.requires_account_input(algorithm::composition::type::ed25519, std::move(signable_link), wallet.public_key, (uint8_t*)signable_message.data(), signable_message.size(), { { asset, decimal("100.00001") } });
			prepared.requires_account_output("GD4QDZNYKL4VH7QGVP47DZZBEUB5KR53SI2RACPDNTHCOSAQJTN3RW2Z", { { asset, decimal("100") } });
			prepared.requires_abi(format::variable((uint64_t)1561327986278403));
			prepared.requires_abi(format::variable((uint32_t)1));
			prepared.requires_abi(format::variable((uint32_t)0));
			prepared.requires_abi(format::variable(true));
			prepared.requires_abi(format::variable(string()));
			prepared.requires_abi(format::variable(string()));
			prepared.requires_abi(format::variable((uint32_t)0));
			validate_transaction(asset, wallet, prepared, "create_account", "AAAAACqZSpWEFKnawEf9MgAYR5VPifRkQzywQmb9431q/xVEAAAAZAAFjAUAAAADAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAA+QHluFL5U/4Gq/nx5yElA9VHu5I1EAnjbM4nSBBM27gAAAAAO5rKAAAAAAAAAAABav8VRAAAAEDwmgeOy3MUl/nyANi/pKs/m6EpmQa3fibonYTDwT3ZUt0Md36qD5xX9aNtqqaCyDyjNiTeXeyJKs8IPai0i+AG");
		});
		use_clean_state([&]()
		{
			auto asset = algorithm::asset::id_of("SOL");
			auto state = storages::oraclestate(asset);
			auto wallet = create_wallet(asset);

			auto signable_link = oracle::wallet_link(user.public_key_hash, wallet.encoded_public_key, wallet.encoded_addresses.begin()->second);
			auto signable_message = codec::hex_decode("0x80010001032a994a958414a9dac047fd32001847954f89f464433cb04266fde37d6aff15440963cbfdea28293c02cd965c46e7a6f26bc5f26da4fa00dda8c8ade49f96dcad0000000000000000000000000000000000000000000000000000000000000000b83691e4405ab95ed6264b5942eb150deb64c9d0688940be0f6548da25de783c01020200010c02000000f86677230100000000");
			oracle::prepared_transaction prepared;
			prepared.requires_account_input(algorithm::composition::type::ed25519, std::move(signable_link), wallet.public_key, (uint8_t*)signable_message.data(), signable_message.size(), { { asset, decimal("4.890005") } });
			prepared.requires_account_output("devwuNsNYACyiEYxRNqMNseBpNnGfnd4ZwNHL7sphqv", { { asset, decimal("4.89") } });
			prepared.requires_abi(format::variable((uint64_t)1000000000));
			prepared.requires_abi(format::variable(string()));
			prepared.requires_abi(format::variable(string()));
			prepared.requires_abi(format::variable(string()));
			prepared.requires_abi(format::variable(string("DQ6H97iaf92qFZAWFSu57x74i47L4MJL5vjfun8pMrCj")));
			prepared.requires_abi(format::variable(decimal("0.000005")));
			validate_transaction(asset, wallet, prepared, "transfer", "29pzeBNzkH9kVYkdLFazEy6gfZ9NgqNNx1McqnL2bmruWJtQukd1fxm6s4EcmAPbsk7grZBpQes8rSAPPxuqjesqZJHEhW3ohBfxjwwRRbq8DT5VkUqYBVvNv4cMYHvB1tv9zC26unsLpTPis8joMxrnvwbqSoA7LrqAV3V7snqh7W7rVLMwYz9eydbRxS8uPBBSwNyk9jsZcQXdPDcccuJq9M3QMUw6sXzD2FQ69FuMDuMZqDNwBbqhzDz9uorRnHFhYmM2pvQsqVY7cuyYWqXCVXaWLuCWuLygvzLw");

			auto token_asset = algorithm::asset::id_of("SOL", "9YaGkvrR1fjXSAm7LTcQYXZiZfub2EuWvVxBmRSHcwHZ", "9YaGkvrR1fjXSAm7LTcQYXZiZfub2EuWvVxBmRSHcwHZ");
			signable_link = oracle::wallet_link(user.public_key_hash, wallet.encoded_public_key, wallet.encoded_addresses.begin()->second);
			signable_message = codec::hex_decode("0x80010001042a994a958414a9dac047fd32001847954f89f464433cb04266fde37d6aff1544437b32d02edb961d6ffba969407c441a127befb1fe6885fa40f3d9e1dd7f9306d36dc35d5d43cb85d730bbf57899cb2266076f149fdf00b5491b69d1ad764df306ddf6e1d765a193d9cbe146ceeb79ac1cb485ed5f5b37913a8cf5857eff00a95abee248b8b08441f683b2e58d6b7c62bfa977bb775f0ef37facee593d0b1269010303010200090350a505000000000000");
			prepared = oracle::prepared_transaction();
			prepared.requires_account_input(algorithm::composition::type::ed25519, std::move(signable_link), wallet.public_key, (uint8_t*)signable_message.data(), signable_message.size(), { { asset, decimal("0.000015") }, { token_asset, decimal("3700") } });
			prepared.requires_account_output("4Bs1nFL71Yaq2HJ3pSk3WHdbhkWeqnrLYQZDhqjDfb53", { { token_asset, decimal("3700") } });
			prepared.requires_abi(format::variable((uint64_t)100));
			prepared.requires_abi(format::variable(string("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")));
			prepared.requires_abi(format::variable(string("5YRGqmfQGcAii8szURA3ZztXfpre1ZnajJcS63GJi4yK")));
			prepared.requires_abi(format::variable(string("FEL6m5CE2P3JTW1ceo48VerTUSWDte6eXzgrcmcftvyQ")));
			prepared.requires_abi(format::variable(string("77EWfi8yvGJNRsC9BRHepMtBJ2RDEDAkZNWAT4YJNMYU")));
			prepared.requires_abi(format::variable(decimal("0.000015")));
			validate_transaction(asset, wallet, prepared, "spl transfer", "2T9rSsJqTD5Ln5iN8E1RGsvHQP59e1oVY2vwWw47WM4xEMuLEnL7w8kzhUdxpCbayLgtqurRJjDCFndHomYaFcNqktTTaj6n6AmonEBLpoXGVrWkWXyBW3w5JvdRQcAwk93ZKbbswzCkFp2wndJfHdsMQ2JokWMbcpp7Jqkp9AvbxM6GzyA6xstN6MpThXXESEUWwZqjVyXccVkes26pviERpfbAc3A7xXBhNibnXXJ9WFwdG3NBrF5ZraFutB7DXoTTKgPSJSFVvhh1bREkinja6j9PR5FzDJ5mXicfkn2x2iekCy4xDrX13ZyNmDo8gzQ34XwjW38J5y93D");
		});
		use_clean_state([&]()
		{
			auto asset = algorithm::asset::id_of("ADA");
			auto state = storages::oraclestate(asset);
			auto wallet = create_wallet(asset);

			auto input_hash = codec::hex_decode("0x14b33fbdd10c0931057b2c66e56b08cf01523480769153e3433050c571dc23e6");
			oracle::coin_utxo input;
			input.link = oracle::wallet_link(user.public_key_hash, wallet.encoded_public_key, wallet.encoded_addresses[1]);
			input.transaction_id = "f887787271fa3538f574bb0a95f1178377dd70a98813657764241fdf4e0ca7b7";
			input.index = 1;
			input.value = decimal("9965.667678");

			oracle::coin_utxo output_1;
			output_1.link = oracle::wallet_link::from_address("addr_test1vqeux7xwusdju9dvsj8h7mca9aup2k439kfmwy773xxc2hcu7zy99");
			output_1.index = 0;
			output_1.value = decimal("2100");

			oracle::coin_utxo output_2;
			output_2.link = input.link;
			output_2.index = 1;
			output_2.value = decimal("7865.501517");

			oracle::prepared_transaction prepared;
			prepared.requires_input(algorithm::composition::type::ed25519, wallet.public_key, (uint8_t*)input_hash.data(), input_hash.size(), std::move(input));
			prepared.requires_output(std::move(output_1));
			prepared.requires_output(std::move(output_2));
			prepared.requires_abi(format::variable((uint64_t)166161));
			validate_transaction(asset, wallet, prepared, "p2pkh", "84a30081825820f887787271fa3538f574bb0a95f1178377dd70a98813657764241fdf4e0ca7b7010182a200581d6033c378cee41b2e15ac848f7f6f1d2f78155ab12d93b713de898d855f011a7d2b7500a200581d6042a00dfc0e9577dd74673d4b90b1e4a00e8a7fe0778dd134d268a95f011b00000001d4d2074d021a00028911a100818258202a994a958414a9dac047fd32001847954f89f464433cb04266fde37d6aff15445840e28a2e306c97c2c3871d64c5830ac0ae2a8e575a699130075c55b67ab3029a5c83712d9e86b71dce110141bf4c8039f388c0e79eccb10c2b4f0a9e3abe08ce0df5f6");

			auto token_contract = "bd976e131cfc3956b806967b06530e48c20ed5498b46a5eb836b61c2";
			auto token_symbol = "tMILKv2";
			input_hash = codec::hex_decode("0x66bb498dd4f2840ef018b8392c58fd198f334474b5c9b96d7412b1b4cee39b0b");
			input = oracle::coin_utxo();
			input.link = oracle::wallet_link(user.public_key_hash, wallet.encoded_public_key, wallet.encoded_addresses[1]);
			input.transaction_id = "0f7cad6020aaf0c462cfb6cba2b5f4102910b7bf7101ed609eb887188b19ad6f";
			input.index = 1;
			input.value = decimal("9940.752346");
			input.apply_token_value(token_contract, token_symbol, decimal("999995689"), 0);

			output_1 = oracle::coin_utxo();
			output_1.link = oracle::wallet_link::from_address("addr_test1vzpkkthr9azvuagxcf0m27qvzdad7n95jutgcdtglgmhdns998vsz");
			output_1.index = 0;
			output_1.value = decimal("1.655136");
			output_1.apply_token_value(token_contract, token_symbol, decimal("65483"), 0);

			output_2 = oracle::coin_utxo();
			output_2.link = input.link;
			output_2.index = 1;
			output_2.value = decimal("9938.927089");
			output_2.apply_token_value(token_contract, token_symbol, decimal("999930206"), 0);

			prepared = oracle::prepared_transaction();
			prepared.requires_input(algorithm::composition::type::ed25519, wallet.public_key, (uint8_t*)input_hash.data(), input_hash.size(), std::move(input));
			prepared.requires_output(std::move(output_1));
			prepared.requires_output(std::move(output_2));
			prepared.requires_abi(format::variable((uint64_t)170121));
			validate_transaction(asset, wallet, prepared, "p2pkh asset", "84a300818258200f7cad6020aaf0c462cfb6cba2b5f4102910b7bf7101ed609eb887188b19ad6f010182a200581d60836b2ee32f44ce7506c25fb5780c137adf4cb497168c3568fa3776ce01821a00194160a1581cbd976e131cfc3956b806967b06530e48c20ed5498b46a5eb836b61c2a147744d494c4b763219ffcba200581d6042a00dfc0e9577dd74673d4b90b1e4a00e8a7fe0778dd134d268a95f01821b000000025067fdf1a1581cbd976e131cfc3956b806967b06530e48c20ed5498b46a5eb836b61c2a147744d494c4b76321a3b99b95e021a00029889a100818258202a994a958414a9dac047fd32001847954f89f464433cb04266fde37d6aff154458404a594cc96cd2aec42c68556ca1c90b06da654230fae3247e14e50d6896598352a6bbe24a45fc825bcae90161c2cad02faf343fdc8354e89ae676b27c8f646304f5f6");
		});
		use_clean_state([&]()
		{
			auto asset = algorithm::asset::id_of("TRX");
			auto state = storages::oraclestate(asset);
			auto wallet = create_wallet(asset);

			auto signable_link = oracle::wallet_link(user.public_key_hash, wallet.encoded_public_key, wallet.encoded_addresses.begin()->second);
			auto signable_message = codec::hex_decode("0x6c30ab9d12ae48c5c6800533451ef201dcc807980ea18739301ac48c2ddef3ce");
			oracle::prepared_transaction prepared;
			prepared.requires_account_input(algorithm::composition::type::secp256k1, std::move(signable_link), wallet.public_key, (uint8_t*)signable_message.data(), signable_message.size(), { { asset, decimal("22.4") } });
			prepared.requires_account_output("TXNE2M4GSw6tjVsGeux9nbVEhihGU6hBeV", { { asset, 14 } });
			prepared.requires_abi(format::variable(string()));
			prepared.requires_abi(format::variable("091a"));
			prepared.requires_abi(format::variable("844ba957b61a108b"));
			prepared.requires_abi(format::variable((uint64_t)1744587342000));
			prepared.requires_abi(format::variable((uint64_t)1744587282000));
			prepared.requires_abi(format::variable((uint32_t)1000000));
			validate_transaction(asset, wallet, prepared, "transfer", "78da8d52cb6edc300cfc179d839494443df6da5e7aef2d080c4aa212a3def5c2f6e68120ff5eba6983b4bdd4be48c3d70c352fe6615cc7328939749e56b932dbd3d72fe6604275c02537b42c3e55aa210190739e50ba056cb52688398130a6e8b203e4aa89b635e9ae8ab9320b3f0e8d371eeee5493b0283858c6c2da4e47de14cb1046484543c14489872aae29c25d66109106df0c0b6451f73844056420c5dff186aa0808ae5e814758a35db23441b7af47adb916a85bc221824ba100245eb775ce21beaa247eb542692c7aa5a6a537abd6590aa3d6ac68cd89a8f52a4510b25844c68f76ce142d0152a410972d03912894a256c29d7a2d99843f2981214cd8310a101d7446f0a33002660579d8f1f36650e2fa6cea76de1ba99c3cd8b39f3c247d964d9230f3c5d643f6cf3c0ad2db2aebad6ff27a383e6c7932c7f14ffaf6e2de6e37c39292ff4f0f37b55b33c9f65b82c93b6da8fd777f37c37099fc7f5bacec74fe765dee63a4fd7df163ead5d96cfbfc5fdaad5ba7f43b7ba10e94399e6fa7d28cf9bec4c77e7988f817b5eef15ffdb499a234fe771e16d9c4fca357a4fea4f6f95b0ce1c8fb26e7c3cbf476c7a8b7491611a8fe3ae8fe05de03ade9d78bb2ccaf4c66885ee878bad1d2526921ec9aaf5d54fb46f4d1fb8e7c41ca920546f111abbd2a5abe1256081c8a84fd4212475b125ef441b052a6a714aaa02599a5517b3f35a9bc079c6dc804ab660316035b7af3f00d54e1100");

			auto token_asset = algorithm::asset::id_of("TRX", "GFC", "TUiyUe3uqtiT8cFkfhW6Q28Z99sY7o82Xr");
			signable_link = oracle::wallet_link(user.public_key_hash, wallet.encoded_public_key, wallet.encoded_addresses.begin()->second);
			signable_message = codec::hex_decode("0xc7654e7252c5133d358940cbffff610443358dc18c0411225d7d2596952dfc07");
			prepared = oracle::prepared_transaction();
			prepared.requires_account_input(algorithm::composition::type::secp256k1, std::move(signable_link), wallet.public_key, (uint8_t*)signable_message.data(), signable_message.size(), { { asset, decimal("14.0228") }, { token_asset, decimal("8") } });
			prepared.requires_account_output("TXNE2M4GSw6tjVsGeux9nbVEhihGU6hBeV", { { token_asset, decimal("8") } });
			prepared.requires_abi(format::variable("TUiyUe3uqtiT8cFkfhW6Q28Z99sY7o82Xr"));
			prepared.requires_abi(format::variable("08ca"));
			prepared.requires_abi(format::variable("9dd563feb883a59e"));
			prepared.requires_abi(format::variable((uint64_t)1744587102000));
			prepared.requires_abi(format::variable((uint64_t)1744587042000));
			prepared.requires_abi(format::variable((uint64_t)1000000));
			validate_transaction(asset, wallet, prepared, "trc20 transfer", "78dacd54cb6edc300cfc179d8394a4de7b6d2f3db7b720585012b531ea8d17b6f342907f2fdd24455ab440d05365c09086a4c4e1887a34b7c3329451ccaef3b8c89959ef3f7f323b5363f04e2279aa1ead6dd6a7eca096ae2320386715691553058748e45b6ce473c89e5aaf10cd9999f96edf78e5fd95dceb8ec040902a93fe736b3ed82e2525cb3e8b83022c9d53116bc9330b2024ec489c75c616a38b3942f0242186ae5f0c35f8808ae56815b58a35ea1122851e9dae36a49278a748567f65a47c6c681a455119a85de266c560a343c580d13bac31a7da32726f19a4ea5e3563466ccd4529d27c0b252853a41fdead64171a13927457148b5617a9054ebe8b4bdd06022b44ce291b9f6b29f097e150b878e87a4009c0c42a4294e87d51155ad2503d1b73807f1e9191f40f0d5aeee1b9de19009316b95af75637b37b3475ba5e67aeabd95d3c9a13cf7c9455e6cd72cbe38d6c936757f3bf505302d3ddb5cc7b6e6d9665d1d4deafa806bf32fe35fe9d1a9b276da08793ec6fe65103b7e9f9619a0ea3f06958ceeb74fc709aa775aad378fe751e0e0799bf1c795e3fbe96f9255e63ff6cbe5479a4efcb38d56ffbf2b0ca96dfd655e6ade18a972bc57fef32f591fbd330f33a4cd766a73de57c8aa86d09a0e70e4759563e9e7e5ac03d5bbac87e1c8e83de02f42fc5d64497e170cdebcdacd95e98a84f448aae3039c1add2c2d5b6e4522afa3654a49a0863ecd5390c0e1ce456557da72dac1d5a9d678f924b0db61131d8ec105a4f949c5e9042ba41a2d07ce46e3d41cf1073d06472cfdd4a8582d55c3e7d07fed2526c");
		});
	}
	/* blockchain containing all transaction types (zero balance accounts, valid regtest chain) */
	static void blockchain_full_coverage(vector<account>* userdata)
	{
		use_clean_state([&]()
		{
			uptr<schema> data = userdata ? nullptr : var::set::array();
			vector<algorithm::pubkeyhash_t> contracts;
			vector<account> users =
			{
				account(ledger::wallet::from_seed("000001"), 0),
				account(ledger::wallet::from_seed("000000"), 0),
				account(ledger::wallet::from_seed("000002"), 0)
			};
			TEST_BLOCK(&generators::validator_registration_full, "0xc42f1aadc35cca7dcffe0c864cb7f4e5d085c2e69ddf59850d83840ceff3d799", 1);
			TEST_BLOCK(std::bind(&generators::validator_enable_validator, std::placeholders::_1, std::placeholders::_2, 2, false, true, false), "0x03b804f31c92b018308f27f0aac83c5a11b079555ede703cf04e9ce72eb2ea86", 2);
			TEST_BLOCK(&generators::depository_registration_full, "0x98674c75a62a81a46c2c80a0e09ec9667b3b274e9d576e481d21cc90cc813504", 3);
			TEST_BLOCK(&generators::depository_account_registration_full_stage_1, "0x1d8f42ec4307ba8b3071f2d4b1a06a115f8bbbfcc301e26fed5bed2793f0c1e6", 4);
			TEST_BLOCK(&generators::depository_account_registration_full_stage_2, "0x1db04b87cb11a6b9a18809ede39aa087d0d9ad28d8d3b7df3406851c87a67e60", 6);
			TEST_BLOCK(&generators::depository_attestation_registration_full, "0xf301166fdafc509549dbfa28a097db753273b088e597c43ac252e0c40bb8bc59", 9);
			TEST_BLOCK(&generators::account_transfer_stage_1, "0x0d9309dd544d68a0d82e0dd7b961be7e84826692f326b3c8e21b1052088c63a0", 10);
			TEST_BLOCK(&generators::account_transfer_stage_2, "0x23939db91cf148dde0e45c777d67a1d044b70f0e277f6c5bb4887b2f25f6c45d", 11);
			TEST_BLOCK(std::bind(&generators::account_transfer_to_account, std::placeholders::_1, std::placeholders::_2, 0, algorithm::asset::id_of("BTC"), users[2].wallet.get_address(), 0.05), "0x07825b5d65d288657d5ec8724da247efb0b7b8826f8dd9355f174faf88ed95f7", 12);
			TEST_BLOCK(std::bind(&generators::account_upgrade_stage_1, std::placeholders::_1, std::placeholders::_2, &contracts), "0x8d30d266ebaea6ce5424564c71e6707dc0a562c14c843c7fa2f2db1d86013cb7", 13);
			TEST_BLOCK(std::bind(&generators::account_upgrade_stage_2, std::placeholders::_1, std::placeholders::_2, &contracts), "0x28981198d4cdda4fcd00f66303684beccc38cd978011d9809cd4d9a197ca133a", 14);
			TEST_BLOCK(std::bind(&generators::account_call, std::placeholders::_1, std::placeholders::_2, &contracts), "0x86cd4e2e27c6e5520ee44e3e898f725f66a2ed5585e6c72606a273562e0f8f07", 15);
			TEST_BLOCK(&generators::account_transaction_rollup, "0xb0fb1f72280ab6f4fbf61ae814b76d4ff7f619dab33df9bed11dc5ae22cb0986", 16);
			TEST_BLOCK(std::bind(&generators::validator_enable_validator, std::placeholders::_1, std::placeholders::_2, 2, false, false, true), "0x306e8af2d3564758e7fedf95636ad33b83b4d5fbb48ddbe8ce149c9492f5de18", 17);
			TEST_BLOCK(&generators::depository_migration, "0x3e50a5584d639ff19050cb5949c049b9ac98747602dcc25da6c2ee1569249f9c", 18);
			TEST_BLOCK(&generators::depository_withdrawal_stage_1, "0x3ce971467904499cab6531340dd080316a37511d4bcb4cbcb125547f855d6e41", 20);
			TEST_BLOCK(&generators::depository_withdrawal_stage_2, "0x0f57d0d94dd10ee8091e0ec1fec32680d669b489990b362430228e442a9f140d", 23);
			TEST_BLOCK(&generators::depository_withdrawal_stage_3, "0xf939c7b603493166a37a144586b7d15c1c8201a490930f506af7a16e1e5021e9", 26);
			TEST_BLOCK(&generators::depository_withdrawal_stage_4, "0x907aebeee93efa6da255557e26eb118ab1fb0fcd5c9e46314cd4403f253182db", 29);
			TEST_BLOCK(std::bind(&generators::validator_disable_validator, std::placeholders::_1, std::placeholders::_2, 2, false, true, false), "0x4d8640781af19c66e550c51fe7b638ac2df26ce01299441af26a4100efa43d02", 32);
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
			TEST_BLOCK(&generators::validator_registration_partial, "0xcd03481911e9b631529a514f21ccf34801066dcf733133b437d23ab2fe382726", 1);
			TEST_BLOCK(&generators::depository_registration_partial, "0x6102ec3052e77174c4d10f4d55ed00a93dd0512c8854ec7f47ea73acdca956f2", 2);
			TEST_BLOCK(&generators::depository_account_registration_partial, "0x80e6c9902e0c4385c94312203ebd79a5d7529460c0eb2e18f1ba45647fd3295c", 3);
			TEST_BLOCK(&generators::depository_attestation_registration_partial, "0x2809acb049cf52e5c347d74d123272448ab97759b8a99900a52975f746020c62", 5);
			TEST_BLOCK(std::bind(&generators::account_transfer_to_account, std::placeholders::_1, std::placeholders::_2, 0, algorithm::asset::id_of("BTC"), "tcrt1x00g22stp0qcprrxra7x2pz2au33armtfc50460", 0.1), "0x9921c11ef706ae5fd4c7f0c88ffbc8ea2dc0b94720a71ba1f317b4166276f0ca", 6);
			TEST_BLOCK(std::bind(&generators::account_transfer_to_account, std::placeholders::_1, std::placeholders::_2, 0, algorithm::asset::id_of("ETH", "USDT", "0xdAC17F958D2ee523a2206206994597C13D831ec7"), "tcrt1x00g22stp0qcprrxra7x2pz2au33armtfc50460", 5000), "0x6ad37958343968411239d3903ea1b431ca75b1017d0199ec53809a51fc694e03", 7);
			if (userdata != nullptr)
				*userdata = std::move(users);
			else
				console::get()->jwrite_line(*data);
		});
	}
	/* blockchain exclusively for testing depositories of specific networks (possibly non-zero balance accounts, valid regtest chain) */
	static void blockchain_integration_coverage(const algorithm::asset_id& asset, const unordered_map<string, string>& urls, uint64_t block_number, const decimal& deposit_value, const decimal& depository_fee, std::function<string()>&& new_account, std::function<void(const std::string_view&, bool)>&& new_block, std::function<void(const std::string_view&, const std::string_view&, const decimal&)>&& new_transaction)
	{
		use_clean_state([&]()
		{
			auto* term = console::get();
			auto producers = vector<account>({ account(ledger::wallet::from_seed("000001"), 0), account(ledger::wallet::from_seed("000002"), 0) });
			auto& [user1, user1_nonce] = producers[0];
			auto& [user2, user2_nonce] = producers[1];
			auto [user3, user3_nonce] = account(ledger::wallet::from_seed("000003"), 0);
			auto* validator_adjustment = memory::init<transactions::validator_adjustment>();
			validator_adjustment->asset = asset;
			validator_adjustment->enable_block_production();
			validator_adjustment->allocate_attestation_stake(asset, decimal::zero());
			validator_adjustment->allocate_participation_stake(asset, decimal::zero());
			validator_adjustment->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
			new_block_from_one(nullptr, producers, validator_adjustment);

			validator_adjustment = memory::init<transactions::validator_adjustment>();
			validator_adjustment->asset = asset;
			validator_adjustment->allocate_attestation_stake(asset, decimal::zero());
			validator_adjustment->allocate_participation_stake(asset, decimal::zero());
			validator_adjustment->sign(user2.secret_key, user2_nonce++, decimal::zero()).expect("pre-validation failed");
			new_block_from_one(nullptr, producers, validator_adjustment);

			auto* depository_adjustment = memory::init<transactions::depository_adjustment>();
			depository_adjustment->asset = asset;
			depository_adjustment->set_reward(depository_fee, depository_fee);
			depository_adjustment->set_security(2, decimal::zero(), true, true);
			depository_adjustment->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
			new_block_from_one(nullptr, producers, depository_adjustment);

			auto* depository_account = memory::init<transactions::depository_account>();
			depository_account->asset = asset;
			depository_account->set_manager(user1.public_key_hash);
			depository_account->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
			new_block_from_one(nullptr, producers, depository_account);

			auto& config = protocol::change();
			config.user.oracle.server = true;

			auto* server = oracle::server_node::get();
			auto params = (oracle::relay_backend::chainparams*)server->get_chainparams(asset);
			auto& options = server->get_options();
			params->sync_latency = 0;
			options.polling_frequency_ms = 3000;

			std::mutex mutex;
			std::condition_variable condition;
			std::atomic<int> transaction_status = 0;
			auto receive_transaction = [&]()
			{
				auto time = date_time().milliseconds();
				term->write_line("awaiting transaction log confirmation (checking every 3 seconds for 60 seconds)");
				std::unique_lock<std::mutex> unique(mutex);
				server->trigger_node_activity(asset);
				while (transaction_status != 1)
				{
					condition.wait_for(unique, std::chrono::milliseconds(1000), [&]() { return transaction_status != 0; });
					if (transaction_status == -1)
					{
						time = date_time().milliseconds();
						transaction_status = 0;
					}
					VI_PANIC(date_time().milliseconds() - time <= 60000, "transaction log activity stalled for more than 60 seconds");
				}
				transaction_status = 0;
			};
			server->add_multi_node(asset, unordered_map<string, string>(urls), 0);
			server->add_transaction_callback("logging", [&](const algorithm::asset_id& asset, const oracle::chain_supervisor_options& options, oracle::transaction_logs&& logs) -> expects_lr<void>
			{
				auto transactions = vector<uptr<ledger::transaction>>();
				for (auto& receipt : logs.finalized)
				{
					auto* transaction = memory::init<transactions::depository_attestation>();
					transaction->asset = asset;
					transaction->set_computed_proof(std::move(receipt));
					transactions.push_back(transaction);
				}

				bool log_acquired = !transactions.empty();
				if (log_acquired)
					new_block_from_list(nullptr, producers, std::move(transactions));

				std::unique_lock<std::mutex> unique(mutex);
				transaction_status = log_acquired ? 1 : (transaction_status.load() <= 0 ? -1 : 1);
				condition.notify_one();
				return expectation::met;
			});
			server->scan_from_block_height(asset, block_number);
			term->write_line("incoming transaction integration:");
			term->fwrite_line(" - account required");

			auto from_account = new_account();
			depository_account = memory::init<transactions::depository_account>();
			depository_account->asset = asset;
			depository_account->set_routing_address(from_account);
			depository_account->set_manager(user1.public_key_hash);
			depository_account->sign(user3.secret_key, user3_nonce++, decimal::zero()).expect("pre-validation failed");
			new_block_from_one(nullptr, producers, depository_account);

			size_t deposits = 0;
			auto context = ledger::transaction_context();
			auto accounts = *context.get_witness_accounts_by_purpose(params->routing == oracle::routing_policy::account ? user1.public_key_hash : user3.public_key_hash, states::witness_account::account_type::depository, 0, 128);
			term->fwrite_line(" - block reward required for account %s", from_account.c_str());
			new_block(from_account, false);
			for (auto& account : accounts)
			{
				if (account.manager == user1.public_key_hash)
				{
					for (auto& [type, to_account] : account.addresses)
					{
						term->fwrite_line(" - deposit %s into %s", deposit_value.to_string().c_str(), to_account.c_str());
						new_transaction(from_account, to_account, deposit_value);
						++deposits;
					}
				}
			}
			VI_PANIC(deposits > 0, "deposit address generation failed");
			new_block(from_account, true);
			server->startup();
			receive_transaction();

			auto expected_balance = (deposit_value - depository_fee) * deposits;
			auto balance = context.get_account_balance(asset, user3.public_key_hash).expect("balance mismatch").get_balance();
			auto withdrawal_value = balance - depository_fee;
			VI_PANIC(balance == expected_balance, "actual balance is expected to be %s but is %s", expected_balance.to_string().c_str(), balance.to_string().c_str());
			term->write_line("outgoing transaction integration:");
			term->fwrite_line(" - withdraw %s into %.*s", withdrawal_value.to_string().c_str(), (int)from_account.size(), from_account.data());

			auto* depository_withdrawal = memory::init<transactions::depository_withdrawal>();
			depository_withdrawal->asset = asset;
			depository_withdrawal->set_manager(user1.public_key_hash);
			depository_withdrawal->set_to(from_account, withdrawal_value);
			depository_withdrawal->sign(user3.secret_key, user3_nonce++, decimal::zero()).expect("pre-validation failed");
			new_block_from_one(nullptr, producers, depository_withdrawal);

			auto chain = storages::chainstate();
			auto confirmation_block = chain.get_latest_block();
			VI_PANIC(confirmation_block && !confirmation_block->transactions.empty(), "blocks with withdrawal confirmation were not found");

			auto& confirmation = confirmation_block->transactions.front();
			VI_PANIC(confirmation.transaction->as_type() == transactions::depository_withdrawal_finalization::as_instance_type(), "no withdrawal confirmation");

			auto* confirmation_event = confirmation.receipt.find_event<transactions::depository_withdrawal_finalization>();
			auto* confirmation_transaction = (transactions::depository_withdrawal_finalization*)*confirmation.transaction;
			VI_PANIC(confirmation_transaction->proof && !confirmation_event, "withdrawal confirmation failed: %s", confirmation_event ? (confirmation_event->empty() ? "unknown error" : confirmation_event->front().as_blob().c_str()) : confirmation_transaction->proof.what().c_str());
			term->fwrite_line(" - block required for transaction %s", confirmation_transaction->proof->hashdata.c_str());
			new_block(from_account, true);
			receive_transaction();

			balance = context.get_account_balance(asset, user3.public_key_hash).or_else(states::account_balance(user3.public_key_hash, asset, nullptr)).get_balance();
			VI_PANIC(balance.is_zero(), "actual balance is expected to be zero but is %s", balance.to_string().c_str());
			server->add_transaction_callback("logging", nullptr);
			server->shutdown();
		});
	}
	/* verify current blockchain */
	static void blockchain_verification()
	{
		auto* term = console::get();
		auto chain = storages::chainstate();
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
				term->jwrite_line(*data);
				VI_PANIC(false, "block verification failed");
			}

			auto proof = next->as_proof(parent_block.address(), &evaluation.state);
			if (next->transaction_root != proof.transaction_tree.root())
			{
				term->jwrite_line(*data);
				VI_PANIC(false, "block verification failed - transaction merkle root deviation");
			}

			if (next->receipt_root != proof.receipt_tree.root())
			{
				term->jwrite_line(*data);
				VI_PANIC(false, "block verification failed - receipt merkle root deviation");
			}

			if (next->state_root != proof.state_tree.root())
			{
				term->jwrite_line(*data);
				VI_PANIC(false, "block verification failed - state merkle root deviation");
			}

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
			for (auto& [index, change] : evaluation.state.finalized)
			{
				uint256_t hash = change.state->as_hash();
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

		algorithm::seckey_t from;
		crypto::fill_random_bytes(from.data, sizeof(from));

		algorithm::pubkeyhash_t to;
		crypto::fill_random_bytes(to.data, sizeof(to));

		auto transaction = transactions::validator_adjustment();
		transaction.set_asset("BTC");
		transaction.enable_block_production();
		transaction.allocate_attestation_stake(algorithm::asset::id_of("ETH"), decimal::zero());
		transaction.allocate_attestation_stake(algorithm::asset::id_of("XRP"), decimal::zero());
		transaction.allocate_attestation_stake(algorithm::asset::id_of("BTC"), decimal::zero());
		transaction.allocate_participation_stake(algorithm::asset::id_of("ETH"), decimal::zero());
		transaction.allocate_participation_stake(algorithm::asset::id_of("XRP"), decimal::zero());
		transaction.allocate_participation_stake(algorithm::asset::id_of("BTC"), decimal::zero());
		VI_PANIC(transaction.sign(from, 1, decimal::zero()), "validator_adjustment not signed");

		uptr<schema> data = var::set::object();
		data->set("validator_adjustment_transaction_gas_limit", algorithm::encoding::serialize_uint256(transaction.gas_limit));
		data->set("block_commitment_limit", algorithm::encoding::serialize_uint256(ledger::block::get_commitment_limit()));
		data->set("block_transaction_limit", algorithm::encoding::serialize_uint256(ledger::block::get_transaction_limit()));
		data->set("block_commitment_gas_limit", algorithm::encoding::serialize_uint256(ledger::block::get_commitment_gas_limit()));
		data->set("block_transaction_gas_limit", algorithm::encoding::serialize_uint256(ledger::block::get_transaction_gas_limit()));
		data->set("block_total_gas_limit", algorithm::encoding::serialize_uint256(ledger::block::get_total_gas_limit()));
		term->jwrite_line(*data);
	}

public:
	template <typename t, typename... args>
	static void new_serialization_comparison(schema* data, args... arguments)
	{
		t instance = t(arguments...); format::wo_stream message;
		VI_PANIC(instance.store(&message), "failed to store a message");

		t instance_copy = t(arguments...);
		auto reader = message.ro();
		VI_PANIC(instance_copy.load(reader), "failed to load a message");

		format::wo_stream message_copy;
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
	static ledger::block new_block_from_one(schema* results, vector<account>& users, uptr<ledger::transaction>&& transaction)
	{
		auto transactions = vector<uptr<ledger::transaction>>();
		transactions.push_back(std::move(transaction));
		return new_block_from_list(results, users, std::move(transactions));
	}
	static ledger::block new_block_from_list(schema* results, vector<account>& users, vector<uptr<ledger::transaction>>&& transactions)
	{
		ledger::evaluation_context environment;
		vector<std::pair<transactions::depository_attestation*, account*>> post_attestations;
		vector<uptr<ledger::transaction>> pre_attestations;
		for (size_t i = 0; i < transactions.size(); i++)
		{
			auto& transaction = transactions[i];
			if (transaction->as_type() != transactions::depository_attestation::as_instance_type())
				continue;

			auto* attestation = (transactions::depository_attestation*)*transaction;
			if (!attestation->proof_or_commitment)
				continue;

			ordered_set<account*> attesters;
			for (auto& user : users)
			{
				auto validator = environment.validation.context.get_validator_attestation(attestation->asset, user.wallet.public_key_hash);
				if (validator && validator->is_active())
					attesters.insert(&user);
			}

			auto* prover = *attesters.begin();
			size_t required_commitments = (size_t)(decimal(attesters.size()) * protocol::now().policy.attestation_consensus_threshold).to_uint64();
			while (attesters.size() > required_commitments)
				attesters.erase(attesters.begin());

			for (auto& committer : attesters)
			{
				auto* additional_attestation = memory::init<transactions::depository_attestation>();
				additional_attestation->asset = attestation->asset;
				additional_attestation->set_commitment(*attestation->proof_or_commitment);
				additional_attestation->sign(committer->wallet.secret_key, committer->nonce++, decimal::zero()).expect("pre-validation failed");
				pre_attestations.push_back(additional_attestation);
			}
			post_attestations.push_back(std::make_pair(attestation, prover));
		}

		if (!post_attestations.empty())
		{
			if (!pre_attestations.empty())
				new_block_from_list(results, users, std::move(pre_attestations));
			for (auto& [attestation, prover] : post_attestations)
				attestation->sign(prover->wallet.secret_key, prover->nonce++, decimal::zero()).expect("pre-validation failed");
		}

		uint64_t priority = std::numeric_limits<uint64_t>::max();
		for (auto& user : users)
		{
			priority = environment.configure_priority_from_validator(user.wallet.public_key_hash, user.wallet.secret_key).or_else(std::numeric_limits<uint64_t>::max());
			if (!priority)
				break;
		}

		VI_PANIC(priority == 0, "block proposal not allowed");
		if (!environment.try_include_transactions(std::move(transactions)))
			VI_PANIC(false, "empty block not allowed");

		auto proposal = environment.evaluate_block(nullptr).expect("block evaluation failed");
		environment.solve_evaluated_block(proposal.block).expect("block solution failed");
		if (results != nullptr)
			environment.verify_solved_block(proposal.block, &proposal.state).expect("block verification failed");

		transactions = vector<uptr<ledger::transaction>>();
		proposal.checkpoint().expect("block checkpoint failed");
		if (results != nullptr)
			results->push(proposal.as_schema().reset());

		vector<ledger::wallet> validators;
		validators.reserve(users.size());
		for (auto& [user, user_nonce] : users)
			validators.push_back(user);

		auto dispatcher = consensus::local_dispatch_context(validators);
		for (auto& [user, user_nonce] : users)
		{
			dispatcher.set_running_validator(user.public_key_hash);
			dispatcher.dispatch_sync(proposal.block);
			if (!dispatcher.outputs.empty())
			{
				for (auto& transaction : dispatcher.outputs)
				{
					if (transaction->as_type() != transactions::depository_attestation::as_instance_type())
						transaction->sign(user.secret_key, user_nonce++, decimal::zero()).expect("pre-validation failed");
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

		auto chain = storages::chainstate();
		chain.clear_indexer_cache();
		callback();
	}
};

class runners
{
public:
	/* consensus, discovery, oracle, rpc nodes */
	static int consensus(inline_args& args)
	{
		auto& params = protocol::now();
		uint32_t test_account = from_string<uint32_t>(args.get("test-account")).expect("must provide a \"test-account\" flag (number)");
		ledger::wallet wallet = ledger::wallet::from_seed(stringify::text("00000%i", test_account - 1));
		ledger::node node;
		node.address = socket_address(params.user.consensus.address, params.user.consensus.port);

		auto mempool = storages::mempoolstate();
		mempool.apply_node(std::make_pair(node, wallet));
		VI_INFO("test using account baseline: %s", wallet.get_address().c_str());

		consensus::server_node consensus_service;
		discovery::server_node discovery_service;
		oracle::server_node& oracle_service = *oracle::server_node::get();
		rpc::server_node rpc_service = rpc::server_node(&consensus_service);

		service_control control;
		control.bind(discovery_service.get_entrypoint());
		control.bind(consensus_service.get_entrypoint());
		control.bind(oracle_service.get_entrypoint());
		control.bind(rpc_service.get_entrypoint());
		return control.launch();
	}
	/* simplest blockchain explorer for debugging */
	static int explorer(inline_args& args)
	{
		auto term = console::get();
		auto chain = storages::chainstate();
		auto mempool = storages::mempoolstate();
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

				algorithm::pubkeyhash_t owner;
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
					row = states::account_multiform::as_instance_row(owner, codec::hex_decode(args[4]));
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

				auto response = index.empty() ? chain.get_multiform(type, nullptr, column, row, 0) : chain.get_uniform(type, nullptr, index, 0);
				if (!response || !*response)
					goto not_found;

				auto data = response->value->as_schema();
				term->jwrite_line(*data);
				continue;
			}
			else if (method == "validator")
			{
				if (args.size() < 3)
					goto not_valid;

				algorithm::pubkeyhash_t owner;
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

				auto response = index.empty() ? chain.get_multiform(type, nullptr, column, row, 0) : chain.get_uniform(type, nullptr, index, 0);
				if (!response || !*response)
					goto not_found;

				auto data = response->value->as_schema();
				term->jwrite_line(*data);
				continue;
			}
			else if (method == "depository")
			{
				if (args.size() < 3)
					goto not_valid;

				algorithm::pubkeyhash_t owner;
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

					algorithm::pubkeyhash_t subject;
					if (!algorithm::signing::decode_address(args[3], subject))
						goto not_valid;

					type = states::depository_account::as_instance_type();
					column = states::depository_account::as_instance_column(owner);
					row = states::depository_account::as_instance_row(algorithm::asset::id_of_handle(args[4]), subject);
				}

				auto response = index.empty() ? chain.get_multiform(type, nullptr, column, row, 0) : chain.get_uniform(type, nullptr, index, 0);
				if (!response || !*response)
					goto not_found;

				auto data = response->value->as_schema();
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

					algorithm::pubkeyhash_t owner;
					if (!algorithm::signing::decode_address(args[2], owner))
						goto not_valid;

					type = states::witness_account::as_instance_type();
					column = states::witness_account::as_instance_column(owner);
					row = states::witness_account::as_instance_row(algorithm::asset::id_of_handle(args[3]), args[4]);
				}
				else if (state == "attestation")
				{
					if (args.size() < 4)
						goto not_valid;

					type = states::witness_attestation::as_instance_type();
					index = states::witness_attestation::as_instance_index(algorithm::asset::id_of_handle(args[2]), algorithm::encoding::decode_0xhex256(args[3]));
				}
				else if (state == "transaction")
				{
					if (args.size() < 4)
						goto not_valid;

					type = states::witness_transaction::as_instance_type();
					index = states::witness_transaction::as_instance_index(algorithm::asset::id_of_handle(args[2]), args[3]);
				}

				auto response = index.empty() ? chain.get_multiform(type, nullptr, column, row, 0) : chain.get_uniform(type, nullptr, index, 0);
				if (!response || !*response)
					goto not_found;

				auto data = response->value->as_schema();
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

				algorithm::pubkeyhash_t owner;
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

				algorithm::pubkeyhash_t owner;
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
					auto* hashes = data->set("changelog", var::set::array());
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
				auto chain = storages::chainstate();
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
					evaluation.block = std::move(*next);

					auto changelog = chain.get_block_state_by_number(evaluation.block.number);
					if (changelog)
						evaluation.state = std::move(*changelog);

					auto evaluation1 = ledger::block_evaluation();
					auto validation = validate ? evaluation.block.validate(parent_block.address(), &evaluation1) : expects_lr<void>(expectation::met);
					auto validity = evaluation.block.verify_validity(parent_block.address());
					auto integrity = evaluation.block.verify_integrity(parent_block.address(), validate ? &evaluation.state : nullptr);
					auto proof = evaluation.block.as_proof(parent_block.address(), validate ? &evaluation.state : nullptr);
					auto block_info = evaluation.as_schema();
					size_t tx_index = 0;
					for (auto& item : block_info->get("transactions")->get_childs())
					{
						auto& tx = evaluation.block.transactions[tx_index++];
						auto* tx_info = item->get("transaction");
						auto* claim_info = item->get("receipt");
						tx_info->set("merkle_test", var::string(proof.has_transaction(tx.receipt.transaction_hash) ? "passed" : "failed"));
						claim_info->set("merkle_test", var::string(proof.has_receipt(tx.receipt.as_hash()) ? "passed" : "failed"));
					}

					if (validate)
					{
						for (auto& item : block_info->get("changelog")->get_childs())
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
				auto chain = storages::chainstate();
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
				format::ro_stream message = format::ro_stream(args[1]);
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

		return 0;
	}
	/* blockchain derived from partial coverage test with 1920 additional blocks filled with configurable entropy transactions (non-zero balance accounts, valid regtest chain, entropy 0 - low entropy, entropy 1 - medium entropy, entropy 2 - high entropy) */
	static int benchmark(inline_args& args)
	{
		auto* term = console::get();
		auto* queue = schedule::get();
		queue->start(schedule::desc());

		const size_t block_count = 250;
		const uint256_t transaction_gas_limit = (size_t)ledger::block::get_transaction_gas_limit();
		const decimal starting_account_balance = decimal(500).truncate(12);
		auto checkpoint = [&](vector<uptr<ledger::transaction>>&& transactions, vector<tests::account>& users)
		{
			static uint64_t cumulative_transaction_count = 0, cumulative_state_count = 0;
			auto cumulative_query_count = (uint64_t)ledger::storage_util::get_thread_invocations(); term->capture_time();
			auto block = tests::new_block_from_list(nullptr, users, std::move(transactions));
			auto time = term->get_captured_time();
			cumulative_transaction_count += block.transaction_count;
			cumulative_state_count += block.state_count;
			term->fwrite_line("%05" PRIu64 ": %s = (d: %s / %.2f ms, t: %" PRIu64 " / %.2f hz, s: %" PRIu64 " / %.2f hz, q: %" PRIu64 " / %.2f hz)",
				block.number, algorithm::encoding::encode_0xhex256(block.as_hash()).c_str(),
				block.target.difficulty().to_string().c_str(), time,
				cumulative_transaction_count, 1000.0 * (double)block.transaction_count / time,
				cumulative_state_count, 1000.0 * (double)block.state_count / time,
				cumulative_query_count, 1000.0 * (double)((uint64_t)ledger::storage_util::get_thread_invocations() - cumulative_query_count) / time);
		};

		vector<tests::account> users;
		tests::blockchain_partial_coverage(&users);

		auto& [user1, user1_nonce] = users[0];
		auto chain = storages::chainstate();
		auto mempool = storages::mempoolstate();
		auto context = ledger::transaction_context();
		auto user1_addresses = *context.get_witness_accounts_by_purpose(user1.public_key_hash, states::witness_account::account_type::depository, 0, 128);
		auto user1_depository_address = std::find_if(user1_addresses.begin(), user1_addresses.end(), [](states::witness_account& item) { return item.asset == algorithm::asset::id_of("BTC"); });
		VI_PANIC(user1_depository_address != user1_addresses.end(), "user 1 depository address not found");

		auto gas_wallet = ledger::wallet::from_seed();
		transactions::transfer gas_transaction;
		gas_transaction.set_asset("BTC");
		gas_transaction.set_to(gas_wallet.public_key_hash, 0.1);
		gas_transaction.sign(user1.secret_key, user1_nonce, decimal::zero()).expect("pre-validation failed");

		size_t transaction_count = (size_t)(transaction_gas_limit / gas_transaction.gas_limit);
		transaction_count = std::min(transaction_count, transaction_count - 10);

		auto entropy = from_string<uint8_t>(args.get("test-entropy")).expect("must provide a \"test-entropy\" flag (number in [1, 2, 3])");
		if (entropy == 1)
		{
			const decimal outgoing_account_balance = starting_account_balance / decimal(block_count * (transaction_count + 64));
			const decimal incoming_quantity = starting_account_balance;
			auto* depository_attestation = memory::init<transactions::depository_attestation>();
			depository_attestation->set_asset("BTC");
			depository_attestation->set_finalized_proof(883669,
				"222fc360affb804ad2c34bba2269b36a64a86f017d05a9a60b237e8587bfc52b",
				{ oracle::value_transfer(depository_attestation->asset, "mmtubFoJvXrBuBUQFf1RrowXUbsiPDYnYS", decimal(incoming_quantity)) },
				{ oracle::value_transfer(depository_attestation->asset, user1_depository_address->addresses.begin()->second, decimal(incoming_quantity)) });
			depository_attestation->sign(user1.secret_key, 0, decimal::zero()).expect("pre-validation failed");

			auto genesis = vector<uptr<ledger::transaction>>();
			genesis.push_back(depository_attestation);
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
					transaction->set_to(receiver.public_key_hash, decimal(outgoing_account_balance).truncate(12) * decimal(balance));
					VI_PANIC(transaction->sign(user1.secret_key, user1_nonce++), "authentication failed");
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
		else if (entropy == 2)
		{
			const size_t sender_count = 16;
			const size_t receiver_count = 32;
			const decimal outgoing_account_balance = starting_account_balance / decimal(block_count * (transaction_count + 64) * sender_count);
			const decimal incoming_quantity = starting_account_balance * sender_count;
			auto* depository_attestation = memory::init<transactions::depository_attestation>();
			depository_attestation->set_asset("BTC");
			depository_attestation->set_finalized_proof(883669,
				"222fc360affb804ad2c34bba2269b36a64a86f017d05a9a60b237e8587bfc52b",
				{ oracle::value_transfer(depository_attestation->asset, "mmtubFoJvXrBuBUQFf1RrowXUbsiPDYnYS", decimal(incoming_quantity)) },
				{ oracle::value_transfer(depository_attestation->asset, user1_depository_address->addresses.begin()->second, decimal(incoming_quantity)) });
			depository_attestation->sign(user1.secret_key, 0, decimal::zero()).expect("pre-validation failed");

			auto genesis = vector<uptr<ledger::transaction>>();
			genesis.push_back(depository_attestation);
			checkpoint(std::move(genesis), users);

			vector<tests::account> senders;
			senders.reserve(sender_count);
			for (size_t i = 0; i < sender_count; i++)
				senders.emplace_back(tests::account(ledger::wallet::from_seed(stringify::text("00001%i", (int)i)), 0));

			vector<tests::account> receivers;
			receivers.reserve(receiver_count);
			for (size_t i = 0; i < receiver_count; i++)
				receivers.emplace_back(tests::account(ledger::wallet::from_seed(stringify::text("00002%i", (int)i)), 0));

			auto* transfer = memory::init<transactions::transfer>();
			transfer->set_asset("BTC");
			for (auto& sender : senders)
				transfer->set_to(sender.wallet.public_key_hash, starting_account_balance);
			transfer->set_gas(decimal::zero(), ledger::block::get_transaction_gas_limit());
			VI_PANIC(transfer->sign(user1.secret_key, user1_nonce++), "authentication failed");

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
					transaction->set_to(receiver.wallet.public_key_hash, decimal(outgoing_account_balance).truncate(12) * decimal(balance));
					VI_PANIC(transaction->sign(sender.wallet.secret_key, sender.nonce++), "authentication failed");
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
		else if (entropy == 3)
		{
			const size_t sender_count = transaction_count;
			const decimal outgoing_account_balance = starting_account_balance / decimal(block_count * (transaction_count + 64) * sender_count);
			const decimal incoming_quantity = starting_account_balance * sender_count * 2;
			auto* depository_attestation = memory::init<transactions::depository_attestation>();
			depository_attestation->set_asset("BTC");
			depository_attestation->set_finalized_proof(883669,
				"222fc360affb804ad2c34bba2269b36a64a86f017d05a9a60b237e8587bfc52b",
				{ oracle::value_transfer(depository_attestation->asset, "mmtubFoJvXrBuBUQFf1RrowXUbsiPDYnYS", decimal(incoming_quantity)) },
				{ oracle::value_transfer(depository_attestation->asset, user1_depository_address->addresses.begin()->second, decimal(incoming_quantity)) });
			depository_attestation->sign(user1.secret_key, 0, decimal::zero()).expect("pre-validation failed");

			auto genesis = vector<uptr<ledger::transaction>>();
			genesis.push_back(depository_attestation);
			checkpoint(std::move(genesis), users);

			vector<tests::account> senders;
			senders.reserve(sender_count);
			for (size_t i = 0; i < sender_count; i++)
				senders.emplace_back(tests::account({ ledger::wallet::from_seed(stringify::text("00001%i", (int)i)), 0 }));

			auto* transfer = memory::init<transactions::transfer>();
			transfer->set_asset("BTC");
			for (auto& sender : senders)
				transfer->set_to(sender.wallet.public_key_hash, starting_account_balance);
			transfer->set_gas(decimal::zero(), ledger::block::get_transaction_gas_limit());
			VI_PANIC(transfer->sign(user1.secret_key, user1_nonce++), "authentication failed");

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
					transaction->set_to(receiver, decimal(outgoing_account_balance).truncate(12) * decimal(balance));
					VI_PANIC(transaction->sign(sender.wallet.secret_key, sender.nonce++), "authentication failed");
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

		auto tip_block = chain.get_latest_block();
		if (tip_block)
		{
			auto block_message = tip_block->as_message();
			term->fwrite_line("benchmark block size: ~%" PRIu64 " bytes", (uint64_t)(block_message.data.size() + 32));
		}

		queue->stop();
		return 0;
	}
	/* test case runner for regression testing */
	static int regression(inline_args& args)
	{
		size_t executions = 0;
		vector<std::pair<std::string_view, std::function<void()>>> cases =
		{
			{ "generic / integer serialization", &tests::generic_integer_serialization },
			{ "generic / integer conversion", &tests::generic_integer_conversion },
			{ "generic / message serialization", &tests::generic_message_serialization },
			{ "cryptography / wesolowski 2048bit", &tests::cryptography_wesolowski },
			{ "cryptography / signatures", &tests::cryptography_signatures },
			{ "cryptography / wallet", &tests::cryptography_wallet },
			{ "cryptography / wallet encryption", &tests::cryptography_wallet_encryption },
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

		auto* term = console::get();
		for (size_t i = 0; i < cases.size(); i++)
		{
			auto& [name, function] = cases[i];
			term->write_color(std_color::black, std_color::yellow);
			term->fwrite("  ===>  %s  <===  ", name.data());
			term->clear_color();
			term->write_char('\n');
			term->capture_time();

			function();

			double time = term->get_captured_time();
			term->write_color(std_color::white, std_color::dark_green);
			term->fwrite("  TEST PASS %.1fms %.2f%%  ", time, 100.0 * (double)(i + 1) / (double)cases.size());
			term->clear_color();
			term->write("\n\n");
		}
		return 0;
	}
	/* test case runner for oracle testing */
	static int integration(inline_args& args)
	{
		auto* term = console::get();
		auto* queue = schedule::get();
		queue->start(schedule::desc());

		auto path = os::path::resolve(args.get("test-file"), *os::directory::get_working(), true).expect("must provide a \"test-file\" with command list");
		auto list = uptr(*schema::from_json(*os::file::read_as_string(path)));
		auto execute = [&](const std::string_view& url, schema* requests, const std::string_view& path, std::function<void(string&)>&& replacer) -> string
		{
			if (!requests || requests->empty())
				return string();

			uptr<schema> request = requests->size() > 1 ? var::set::array() : var::set::object();
			if (requests->size() > 1)
			{
				size_t id = 0;
				for (auto& subrequest : requests->get_childs())
				{
					auto* data = request->push(var::set::object());
					data->set("jsonrpc", var::string("2.0"));
					data->set("method", var::string(subrequest->key));
					data->set("params", subrequest->copy());
					data->set("id", var::integer(id++));
				}
			}
			else
			{
				auto* subrequest = requests->get_childs().front();
				request->set("jsonrpc", var::string("2.0"));
				request->set("method", var::string(subrequest->key));
				request->set("params", subrequest->copy());
				request->set("id", var::integer(1));
			}

			auto escaped_request_content = schema::to_json(*request);
			if (replacer)
				replacer(escaped_request_content);
			stringify::replace(escaped_request_content, "\"", "\\\"");

			auto response_content = string();
			auto command = stringify::text("curl -X POST -H \"Content-Type: application/json\" -d \"%s\" -s %.*s", escaped_request_content.c_str(), (int)url.size(), url.data());
			term->fwrite_line("> %s", command.c_str());

			std::this_thread::sleep_for(std::chrono::milliseconds(3000));
			int exit_code = os::process::execute(command, file_mode::read_only, [&response_content](const std::string_view& buffer)
			{
				response_content.append(buffer);
				return true;
			}).expect("command failed");
			VI_PANIC(exit_code == 0, "command exit code is non-zero");

			auto response = uptr(schema::from_json(response_content).expect("parsing failed"));
			return path.empty() ? response->value.get_blob() : response->fetch_var(path).get_blob();
		};
		for (auto& node : list->get_childs())
		{
			auto& blockchain = node->key;
			if (blockchain.empty() || blockchain.front() == '#')
				continue;

			auto deposit_value = node->get_var("deposit_value").get_decimal();
			auto depository_fee = node->get_var("depository_fee").get_decimal();
			if (!deposit_value.is_positive())
				deposit_value = 50;
			if (!depository_fee.is_positive())
				depository_fee = 0.5;

			unordered_map<string, string> urls;
			auto url_bindings = node->get("url");
			if (url_bindings != nullptr && !url_bindings->value.is(var_type::string))
			{
				for (auto& protocol : url_bindings->get_childs())
					urls[protocol->key] = protocol->value.get_blob();
			}
			else if (url_bindings != nullptr)
				urls["auto"] = url_bindings->value.get_blob();

			auto auto_url = urls.find("auto"), jrpc_url = urls.find("jrpc");
			auto url = auto_url == urls.end() ? (jrpc_url == urls.end() ? string() : jrpc_url->second) : auto_url->second;
			auto block_number = node->has("block_number") ? node->get_var("block_number").get_integer() : 1;
			tests::blockchain_integration_coverage(algorithm::asset::id_of(blockchain), urls, block_number, deposit_value, depository_fee, [&]()
			{
				auto* account = node->get("account");
				if (!account || !account->value.is(var_type::string))
					return execute(url, node->fetch("account.0"), node->fetch_var("account.1").get_blob(), nullptr);

				return account->value.get_blob();
			}, [&](const std::string_view& from_account, bool confirmation)
			{
				auto* reward_block = node->get("block");
				auto* confirmation_block = node->get("confirmation_block");
				auto* block = confirmation ? (confirmation_block ? confirmation_block : reward_block) : reward_block;
				if (!block || !block->value.is(var_type::string) || block->value.get_blob() != "#prompt")
				{
					execute(url, block, std::string_view(), [&](string& content)
					{
						stringify::replace(content, "$from", from_account);
					});
				}
				else if (confirmation)
				{
					term->fwrite_line("block with required transactions exists? (press enter if so)");
					term->read(128);
				}
			}, [&](const std::string_view& from_account, const std::string_view& to_account, const decimal& value)
			{
				auto* transaction = node->get("transaction");
				auto eth_chain = oracle::server_node::get()->get_chain(algorithm::asset::id_of("ETH"));
				auto eth_value = "0x" + eth_chain->to_baseline_value(value).to_string(16);
				if (!transaction || !transaction->value.is(var_type::string) || transaction->value.get_blob() != "#prompt")
				{
					execute(url, transaction, std::string_view(), [&](string& content)
					{
						stringify::replace(content, "$from", from_account);
						stringify::replace(content, "$to", to_account);
						stringify::replace(content, "$value", value.to_string());
						stringify::replace(content, "$eth_value", eth_value);
					});
				}
				else
				{
					term->fwrite_line(
						"transaction with required params exists? (press enter if so)\n"
						" - account %.*s sends %s (%s) to account %.*s", (int)from_account.size(), from_account.data(), value.to_string().c_str(), eth_value.c_str(), (int)to_account.size(), to_account.data());
					term->read(128);
				}
			});
		}

		queue->stop();
		return 0;
	}
};

int main(int argc, char* argv[])
{
	vitex::runtime scope;
	inline_args args = os::process::parse_args(argc, argv, (size_t)args_format::key | (size_t)args_format::key_value);
	protocol params = protocol(args);
	auto* term = console::get();
	term->show();

	int bad_entrypoint_exit_code = 0x39ce8025;
	int exit_code = bad_entrypoint_exit_code;
	auto test = args.get("test");
	if (test == "consensus")
		exit_code = runners::consensus(args);
	else if (test == "explorer")
		exit_code = runners::explorer(args);
	else if (test == "benchmark")
		exit_code = runners::benchmark(args);
	else if (test == "regression")
		exit_code = runners::regression(args);
	else if (test == "integration")
		exit_code = runners::integration(args);
	else if (test == "cell")
		exit_code = entrypoints::cell(args);
	else if (test == "node")
		exit_code = entrypoints::node(args);

	VI_PANIC(exit_code != bad_entrypoint_exit_code, "must provide a \"test\" flag (string in [consensus, explorer, benchmark, regression, integration] or in [cell, node])");
	if (os::process::has_debugger())
	{
		auto* term = console::get();
		term->write("\n");
		term->write_color(std_color::white, std_color::dark_green);
		term->fwrite("  %s TEST PASS  ", stringify::to_upper(test).c_str());
		term->clear_color();
		term->write("\n\n");
		term->read_char();
	}
	return exit_code;
}