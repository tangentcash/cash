#include "tangent/entrypoints.hpp"
#include "tangent/storage/superchainstate.h"
#include "tangent/storage/mempoolstate.h"
#include "tangent/policy/compositions.h"
#include "tangent/policy/delegations.h"
#include "tangent/translation/bitcoin.h"
#include "tangent/internal/sha3.h"
#include <vitex/vitex.h>
#define TEST_BLOCK(x, y, z) tester::new_block_from_generator(data, users, x, #x, y, z, tester::block_type::normal)
#define TEST_BLOCK_FALLBACK(x, y, z) tester::new_block_from_generator(data, users, x, #x, y, z, tester::block_type::fallback)
#define TEST_BLOCK_FAULTY(x, y, z) tester::new_block_from_generator(data, users, x, #x, y, z, tester::block_type::faulty)
#define TEST_BLOCK_FAULTY_UNATTESTED(x, y, z) tester::new_block_from_generator(data, users, x, #x, y, z, tester::block_type::faulty_unattested)

using namespace tangent;

struct account_ref
{
	ledger::wallet wallet;
	std::atomic<uint64_t> nonce;

	account_ref() = default;
	account_ref(const ledger::wallet& new_wallet, uint64_t new_nonce) : wallet(new_wallet), nonce(new_nonce)
	{
	}
	account_ref(account_ref&& other) noexcept : wallet(std::move(other.wallet)), nonce(other.nonce.load())
	{
	};
	account_ref(const account_ref& other) : wallet(other.wallet), nonce(other.nonce.load())
	{
	}
	account_ref& operator= (account_ref&& other) noexcept
	{
		if (&other == this)
			return *this;

		wallet = std::move(other.wallet);
		nonce = other.nonce.load();
		return *this;
	}
	account_ref& operator= (const account_ref& other)
	{
		if (&other == this)
			return *this;

		wallet = other.wallet;
		nonce = other.nonce.load();
		return *this;
	}
};

struct participant_ref
{
	algorithm::composition::keypair keypair;
	algorithm::storage_type<uint8_t, 64> seed;
};

struct tester
{
	enum class block_type
	{
		normal,
		fallback,
		faulty,
		faulty_unattested
	};

	template <typename t, typename... args>
	static void new_serialization_comparison(format::tree& data, args... arguments)
	{
		t instance = t(arguments...); format::wo_stream message;
		VI_PANIC(instance.store(&message), "failed to store a message");

		t instance_copy = t(arguments...);
		auto reader = message.ro();
		VI_PANIC(instance_copy.load(reader), "failed to load a message");

		format::wo_stream message_copy;
		VI_PANIC(instance_copy.store(&message_copy), "failed to store a message");
		VI_PANIC(message_copy.data == message.data, "serialization inconsistency found");

		data.set(t::as_instance_typename(), format::variable(algorithm::encoding::encode_0xhex256(message.hash())));
	}
	static ledger::block_body new_block_from_generator(format::tree* results, vector<account_ref>& users, std::function<void(vector<uptr<ledger::transaction_message>>&, vector<account_ref>&)>&& test_case, const std::string_view& test_case_call, const std::string_view& state_root_hash, uint64_t block_number, block_type type)
	{
		for (auto& user : users)
			user.nonce = user.wallet.get_latest_nonce().or_else(0);

		vector<uptr<ledger::transaction_message>> transactions;
		test_case(transactions, users);

		auto block = new_block_from_list(results, users, std::move(transactions), type);
		auto hash = algorithm::encoding::encode_0xhex256(block.state_root);
		if (results != nullptr)
			console::get()->fwrite_line("TEST_BLOCK%s(%s, \"%s\", %" PRIu64 ");", type == block_type::fallback ? "_FALLBACK" : (type == block_type::faulty ? "_FAULTY" : (type == block_type::faulty_unattested ? "_FAULTY_UNATTESTED" : "")), test_case_call.data(), hash.c_str(), block.number);

		VI_PANIC(state_root_hash.empty() || state_root_hash == hash, "block state root deviation");
		VI_PANIC(!block_number || block_number == block.number, "block number deviation");
		return block;
	}
	static ledger::block_body new_block_from_one(format::tree* results, vector<account_ref>& users, uptr<ledger::transaction_message>&& transaction, block_type type)
	{
		auto transactions = vector<uptr<ledger::transaction_message>>();
		transactions.push_back(std::move(transaction));
		return new_block_from_list(results, users, std::move(transactions), type);
	}
	static ledger::block_body new_block_from_list(format::tree* results, vector<account_ref>& users, vector<uptr<ledger::transaction_message>>&& transactions, block_type type)
	{
		ledger::solver_context solver;
		if (type != block_type::faulty_unattested)
		{
			for (size_t i = 0; i < transactions.size(); i++)
			{
				auto& transaction = transactions[i];
				if (transaction->as_type() != transactions::attestate::as_instance_type())
					continue;

				auto* attestation = (transactions::attestate*)*transaction;
				for (auto& user : users)
				{
					auto validator = solver.state.executor.get_validator_attestation(attestation->asset, user.wallet.public_key_hash);
					if (validator && validator->is_active())
						VI_PANIC(attestation->add_commitment(user.wallet.secret_key), "attestation failed");
				}

				auto& submitter = users.front();
				attestation->sign(submitter.wallet.secret_key, submitter.nonce++, decimal::zero()).expect("pre-validation failed");
			}
		}

		uint64_t priority = solver.apply_validator_state([&](size_t index) { return index < users.size() ? &users[index].wallet : nullptr; }).or_else(std::numeric_limits<uint64_t>::max());
		if (type == block_type::fallback)
		{
			VI_PANIC(users.size() >= 2, "must have another user");
			auto& fallback_wallet = users[1].wallet;
			solver.state.secret_key = fallback_wallet.secret_key;
			solver.state.public_key_hash = fallback_wallet.public_key_hash;
		}
		VI_PANIC(type == block_type::fallback || priority == 0, "block proposal not allowed");
		VI_PANIC(transactions.size() == solver.try_include_unwrapped_transactions(std::move(transactions), true), "some transactions were excluded");

		auto proposal = solver.evaluate_block_inline().expect("block evaluation failed");
		solver.solve_block_inline(proposal).expect("block solution failed");
		if (results != nullptr)
			solver.verify_block(proposal).expect("block verification failed");

		transactions = vector<uptr<ledger::transaction_message>>();
		solver.checkpoint_block(proposal).expect("block checkpoint failed");
		if (results != nullptr)
		{
			auto* blocks_data = results->child("blocks");
			if (!blocks_data)
				blocks_data = results->set("blocks", format::tree::list());
			blocks_data->push(proposal.as_tree());
		}

		vector<ledger::wallet> validators;
		validators.reserve(users.size());
		for (auto& [user, user_nonce] : users)
			validators.push_back(user);

		auto adapter = consensus::local_delegation_adapter(validators);
		auto execution = adapter.execute_dispatcher_on(proposal.block.number).get();
		for (auto& [runner_wallet, transaction] : adapter.emissions)
		{
			for (auto& [user, user_nonce] : users)
			{
				bool attestation = transaction->as_type() == transactions::attestate::as_instance_type();
				if (attestation || user.public_key_hash == runner_wallet->public_key_hash)
				{
					if (!attestation)
						transaction->sign(user.secret_key, user_nonce++, decimal::zero()).expect("pre-validation failed");
					transactions.push_back(std::move(transaction));
					break;
				}
			}
		}

		for (auto& [transaction_hash, error] : solver.transactions.errors)
		{
			VI_PANIC(type == block_type::faulty || type == block_type::faulty_unattested, "%s", error.what());
			if (results != nullptr)
			{
				auto* errors_data = results->child("errors");
				if (!errors_data)
					errors_data = results->set("errors", format::tree::list());

				format::tree error_data;
				error_data.push(algorithm::encoding::serialize_uint256(transaction_hash));
				error_data.push(format::variable(proposal.block.number));
				error_data.push(format::variable("execution"));
				error_data.push(format::variable(error.what()));
				errors_data->push(std::move(error_data));
			}
		}
		for (auto& [transaction_hash, error] : execution.errors)
		{
			VI_PANIC(type == block_type::faulty || type == block_type::faulty_unattested, "%s", error.what());
			if (results != nullptr)
			{
				auto* errors_data = results->child("errors");
				if (!errors_data)
					errors_data = results->set("errors", format::tree::list());

				format::tree error_data;
				error_data.push(algorithm::encoding::serialize_uint256(transaction_hash));
				error_data.push(format::variable(proposal.block.number));
				error_data.push(format::variable("delegation"));
				error_data.push(format::variable(error.what()));
				errors_data->push(std::move(error_data));
			}
		}

		if (!transactions.empty())
			new_block_from_list(results, users, std::move(transactions), type);

		return proposal.block;
	}
	template <typename f>
	static void use_clean_state(f&& callback)
	{
		auto& params = kernel::mparams();
		auto path = params.database.location();
		params.database.reset();
		if (os::directory::is_exists(path))
			os::directory::remove(path).expect("busy file");

		auto chain = storages::chainstate();
		callback();
	}
};

struct generators
{
	static void transfer_stage_1(vector<uptr<ledger::transaction_message>>& transactions, vector<account_ref>& users)
	{
		auto& [user1, user1_nonce] = users[0];
		auto& [user2, user2_nonce] = users[1];
		auto executor = ledger::executor_context(nullptr);

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
	static void transfer_stage_2(vector<uptr<ledger::transaction_message>>& transactions, vector<account_ref>& users)
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
	static void transfer_custom(vector<uptr<ledger::transaction_message>>& transactions, vector<account_ref>& users, size_t user_id, const algorithm::asset_id& asset, const std::string_view& address, const decimal& value)
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
	static void rollup_stage_1(vector<uptr<ledger::transaction_message>>& transactions, vector<account_ref>& users)
	{
		auto& [user1, user1_nonce] = users[0];
		auto& [user2, user2_nonce] = users[1];
		auto* multi_asset_rollup = memory::init<transactions::rollup>();
		multi_asset_rollup->set_asset("ETH");

		auto transfer_ethereum1 = transactions::transfer();
		transfer_ethereum1.set_asset("ETH");
		transfer_ethereum1.set_to(user2.public_key_hash, 0.1);
		VI_PANIC(multi_asset_rollup->import_internal_transaction(transfer_ethereum1), "authentication failed");

		auto transfer_ethereum2 = transactions::transfer();
		transfer_ethereum2.set_asset("ETH");
		transfer_ethereum2.set_to(user2.public_key_hash, 0.2);
		VI_PANIC(multi_asset_rollup->import_internal_transaction(transfer_ethereum2), "authentication failed");

		auto transfer_ethereum3 = transactions::transfer();
		transfer_ethereum3.set_asset("ETH");
		transfer_ethereum3.set_to(user1.public_key_hash, 0.2);
		VI_PANIC(multi_asset_rollup->import_external_transaction(transfer_ethereum3, user2.secret_key, user2_nonce++), "authentication failed");

		auto transfer_ripple1 = transactions::transfer();
		transfer_ripple1.set_asset("XRP");
		transfer_ripple1.set_to(user2.public_key_hash, 1);
		VI_PANIC(multi_asset_rollup->import_internal_transaction(transfer_ripple1), "authentication failed");

		auto transfer_ripple2 = transactions::transfer();
		transfer_ripple2.set_asset("XRP");
		transfer_ripple2.set_to(user2.public_key_hash, 2);
		VI_PANIC(multi_asset_rollup->import_internal_transaction(transfer_ripple2), "authentication failed");

		auto transfer_ripple3 = transactions::transfer();
		transfer_ripple3.set_asset("XRP");
		transfer_ripple3.set_to(user1.public_key_hash, 2);
		VI_PANIC(multi_asset_rollup->import_external_transaction(transfer_ripple3, user2.secret_key, user2_nonce++), "authentication failed");

		auto transfer_bitcoin1 = transactions::transfer();
		transfer_bitcoin1.set_asset("BTC");
		transfer_bitcoin1.set_to(user2.public_key_hash, 0.001);
		VI_PANIC(multi_asset_rollup->import_internal_transaction(transfer_bitcoin1), "authentication failed");

		auto transfer_bitcoin2 = transactions::transfer();
		transfer_bitcoin2.set_asset("BTC");
		transfer_bitcoin2.set_to(user2.public_key_hash, 0.002);
		VI_PANIC(multi_asset_rollup->import_internal_transaction(transfer_bitcoin2), "authentication failed");

		auto transfer_bitcoin3 = transactions::transfer();
		transfer_bitcoin3.set_asset("BTC");
		transfer_bitcoin3.set_to(user1.public_key_hash, 0.002);
		VI_PANIC(multi_asset_rollup->import_external_transaction(transfer_bitcoin3, user2.secret_key, user2_nonce++), "authentication failed");

		multi_asset_rollup->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(multi_asset_rollup);
	}
	static void deploy_stage_1(vector<uptr<ledger::transaction_message>>& transactions, vector<account_ref>& users, vector<algorithm::pubkeyhash_t>* contracts)
	{
		auto& [user1, user1_nonce] = users[0];
		string token_program = *algorithm::encoding::unpack_program(codec::base64_decode("eNq1VduO2jAQfQaJfxjxUCXa3ahq37JQ9U+QSSbIqmOnjgNF1f57fU1swqWrbnkiM8PMmXPOhIqRvgclfiDf9UpIcsDV8vdquSB1LVGnauyYOKN8jWKV4EqSSsUxUlVi4DbUK0n5AThpMXrsz+1eMBOQSNjXL5+hH7qOnXXkbbVcLasIie7O+wZlCqWRoo1HKhF3OxI2YGh2JPKsh26Sxb657q+2QNDa7KHBDZXKunZQ359dABzgT5R7zPO4WS1EPRoTJnVLeYh7XCZuoeVuGYk/Byoxs7GiEz1V9IhZ/gxryhgeCAPRoSSKCg4vniNoB91xjxDq17lZPdkOOJ52YcHF+FAEAWEL6ldZGhKzPC0JevoSJS4LvLg6b1dMk4YMnQlyTwnHnk5N0tuEKY6wgv4wcShLbKnKxoyFoIfp0MC0Bo5EJ7BVL5gkFS+SQ4kHWsTGmtHzTqFs2Q2dklaw2cKeMMIr3InGL2fG6s7OYR6FjcETrEu4NpDyfmgaWlHUwviGbpz5YbEfJM+cDhKbIjh5ZFFLUVh279SMFgtUAx7R3bj9UnjiwmG6oBKGSzEF3Nrb8UIXk9q2IBbVQkoEfXBHE/zRpLGSN9SavnOhQD9oMArr9Ucrf+NCLUEe98XNuHt/iti6djN/q4x3uHN0Is8Fa3fUmtU+9M09ga0v3yPw/7i/CLvlW/d0LHv6T3oCDLxG2TBxgmytzzC5zcsG9k5hA7NCt5HJ5v/miJcPckT6kossccUqMytMnR6/X657IPxbR2/Aztrg2gvc+200hNIzQ7CIOlSCcvO3pcHMIOV+cMo75Y0Ig9P2sQpvfwAdDwqG"));
		string bridge_program = *algorithm::encoding::unpack_program(codec::base64_decode("eNplj00KwjAUhNcGcofQhSRQiuiu1tKbhGeaSjBNSvJSFfHu/rQuSrfDzDczI4SHcZcK2jboGGuG/qqdBKV8cnikhJLRm5Yp7yKGpJAPfcImnwQ2x7bGMadvchEWlDwp2Sw0dlr7PiUvSoIGe9jv2BksOKWl7yTqiJOVD7+6ZkYGjSm45dQi6K6ICGiUVGBtNQNrnq3Rf976hshyhvey7ILvuRDfbW8xjmV3"));

		auto* deploy1 = memory::init<transactions::deploy>();
		deploy1->from_program(token_program, { format::variable("CAP10"), format::variable("Test Token 0"), format::variable(user1.get_address()), format::variable(decimal(10000u)) });
		deploy1->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(deploy1);
		contracts->push_back(deploy1->get_account());

		auto* deploy2 = memory::init<transactions::deploy>();
		deploy2->from_program(bridge_program, { format::variable(contracts->back().view()) });
		deploy2->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(deploy2);
		contracts->push_back(deploy2->get_account());
	}
	static void deploy_stage_2(vector<uptr<ledger::transaction_message>>& transactions, vector<account_ref>& users, vector<algorithm::pubkeyhash_t>* contracts)
	{
		auto executor = ledger::executor_context(nullptr);
		auto& [user2, user2_nonce] = users[1];
		string testing_program = *algorithm::encoding::unpack_program(codec::base64_decode("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"));

		auto* deploy1 = memory::init<transactions::deploy>();
		deploy1->from_hashcode(executor.get_account_program(contracts->at(0))->hashcode, { format::variable("CAP20"), format::variable("Test Token 1"), format::variable(user2.get_address()), format::variable(decimal(20000u)) });
		deploy1->sign(user2.secret_key, user2_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(deploy1);
		contracts->push_back(deploy1->get_account());

		auto* deploy2 = memory::init<transactions::deploy>();
		deploy2->from_hashcode(executor.get_account_program(contracts->at(1))->hashcode, { format::variable(contracts->back().view()) });
		deploy2->sign(user2.secret_key, user2_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(deploy2);
		contracts->push_back(deploy2->get_account());

		auto* deploy3 = memory::init<transactions::deploy>();
		deploy3->from_program(testing_program, { });
		deploy3->sign(user2.secret_key, user2_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(deploy3);
		contracts->push_back(deploy3->get_account());
	}
	static void call_stage_1(vector<uptr<ledger::transaction_message>>& transactions, vector<account_ref>& users, vector<algorithm::pubkeyhash_t>* contracts)
	{
		auto& [user1, user1_nonce] = users[0];
		auto& [user2, user2_nonce] = users[1];
		auto* call1 = memory::init<transactions::call>();
		call1->call_to(contracts->at(0), "transfer", { format::variable(user2.public_key_hash.view()), format::variable(decimal(1234u)) }, false);
		call1->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(call1);

		auto* call2 = memory::init<transactions::call>();
		call2->call_to(contracts->at(0), "info", { }, false);
		call2->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(call2);

		auto* call3 = memory::init<transactions::call>();
		call3->call_to(contracts->at(2), "transfer", { format::variable(user1.public_key_hash.view()), format::variable(decimal(4321u)) }, true);
		call3->pay_with(algorithm::asset::id_of("TRX"), 10);
		call3->sign(user2.secret_key, user2_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(call3);

		auto* call4 = memory::init<transactions::call>();
		call4->call_to(contracts->at(2), "info", { }, false);
		call4->sign(user2.secret_key, user2_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(call4);

		auto* call5 = memory::init<transactions::call>();
		call5->call_to(contracts->at(1), "balance_of_test_token", { }, false);
		call5->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(call5);

		auto* call6 = memory::init<transactions::call>();
		call6->call_to(contracts->at(3), "balance_of_test_token", { }, false);
		call6->sign(user2.secret_key, user2_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(call6);

		auto* call7 = memory::init<transactions::call>();
		call7->call_to(contracts->at(4), "test_module", { }, false);
		call7->set_gas(decimal::zero(), 500000);
		call7->sign(user2.secret_key, user2_nonce++);
		transactions.push_back(call7);
	}
	static void setup_stage_0(vector<uptr<ledger::transaction_message>>& transactions, vector<account_ref>& users)
	{
		auto& [user1, user1_nonce] = users[0];
		auto* setup_user1 = memory::init<transactions::setup>();
		setup_user1->allocate_production_stake(decimal::zero());
		setup_user1->allocate_participation_stake(decimal::zero());
		setup_user1->allocate_attestation_stake(algorithm::asset::id_of("ETH"), decimal::zero(), 0);
		setup_user1->allocate_attestation_stake(algorithm::asset::id_of("TRX"), decimal::zero(), 0);
		setup_user1->allocate_attestation_stake(algorithm::asset::id_of("BTC"), decimal::zero(), 0);
		setup_user1->allocate_bridge(algorithm::asset::id_of("ETH"), (uint8_t)kernel::params().policy.participation.min_per_account, 0.001);
		setup_user1->allocate_bridge(algorithm::asset::id_of("TRX"), (uint8_t)kernel::params().policy.participation.min_per_account, 20);
		setup_user1->allocate_bridge(algorithm::asset::id_of("BTC"), (uint8_t)kernel::params().policy.participation.min_per_account, 0.0005);
		setup_user1->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(setup_user1);

		for (size_t i = 1; i < users.size(); i++)
		{
			auto& [user_n, user_n_nonce] = users[i];
			auto* setup_user_n = memory::init<transactions::setup>();
			setup_user_n->allocate_participation_stake(decimal::zero());
			setup_user_n->sign(user_n.secret_key, user_n_nonce++, decimal::zero()).expect("pre-validation failed");
			transactions.push_back(setup_user_n);
		}
	}
	static void setup_stage_1(vector<uptr<ledger::transaction_message>>& transactions, vector<account_ref>& users)
	{
		auto& [user1, user1_nonce] = users[0];
		auto& [user2, user2_nonce] = users[1];
		auto* setup_user1 = memory::init<transactions::setup>();
		setup_user1->allocate_production_stake(decimal::zero());
		setup_user1->allocate_participation_stake(decimal::zero());
		setup_user1->allocate_attestation_stake(algorithm::asset::id_of("XRP"), decimal::zero(), 0);
		setup_user1->allocate_bridge(algorithm::asset::id_of("XRP"), (uint8_t)kernel::params().policy.participation.min_per_account, 0.001);
		setup_user1->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(setup_user1);

		auto* setup_user2 = memory::init<transactions::setup>();
		setup_user2->allocate_participation_stake(decimal::zero());
		setup_user2->allocate_attestation_stake(algorithm::asset::id_of("ETH"), decimal::zero(), 0);
		setup_user2->allocate_attestation_stake(algorithm::asset::id_of("XRP"), decimal::zero(), 0);
		setup_user2->allocate_attestation_stake(algorithm::asset::id_of("BTC"), decimal::zero(), 0);
		setup_user2->allocate_attestation_stake(algorithm::asset::id_of("XMR"), decimal::zero(), 0);
		setup_user2->allocate_bridge(algorithm::asset::id_of("ETH"), (uint8_t)kernel::params().policy.participation.min_per_account, 0.0012);
		setup_user2->allocate_bridge(algorithm::asset::id_of("XRP"), (uint8_t)kernel::params().policy.participation.min_per_account, 1.0);
		setup_user2->allocate_bridge(algorithm::asset::id_of("BTC"), (uint8_t)kernel::params().policy.participation.min_per_account, 0.000025);
		setup_user2->allocate_bridge(algorithm::asset::id_of("XMR"), (uint8_t)kernel::params().policy.participation.min_per_account, 0.000025);
		setup_user2->sign(user2.secret_key, user2_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(setup_user2);

		for (size_t i = 3; i < users.size(); i++)
		{
			auto& [user_n, user_n_nonce] = users[i];
			auto* setup_user_n = memory::init<transactions::setup>();
			setup_user_n->allocate_participation_stake(decimal::zero());
			setup_user_n->sign(user_n.secret_key, user_n_nonce++, decimal::zero()).expect("pre-validation failed");
			transactions.push_back(setup_user_n);
		}
	}
	static void setup_stage_2(vector<uptr<ledger::transaction_message>>& transactions, vector<account_ref>& users)
	{
		auto& [user1, user1_nonce] = users[0];
		auto* setup_user1 = memory::init<transactions::setup>();
		setup_user1->allocate_production_stake(decimal::zero());
		setup_user1->allocate_participation_stake(decimal::zero());
		setup_user1->allocate_attestation_stake(algorithm::asset::id_of("BTC"), decimal::zero(), 0);
		setup_user1->allocate_attestation_stake(algorithm::asset::id_of("ETH"), decimal::zero(), 0);
		setup_user1->allocate_attestation_stake(algorithm::asset::id_of("XLM"), decimal::zero(), 0);
		setup_user1->allocate_attestation_stake(algorithm::asset::id_of("XMR"), decimal::zero(), 0);
		setup_user1->allocate_bridge(algorithm::asset::id_of("BTC"), (uint8_t)kernel::params().policy.participation.min_per_account, 0.000025);
		setup_user1->allocate_bridge(algorithm::asset::id_of("ETH"), (uint8_t)kernel::params().policy.participation.min_per_account, 0.0005);
		setup_user1->allocate_bridge(algorithm::asset::id_of("XLM"), (uint8_t)kernel::params().policy.participation.min_per_account, 0.0001);
		setup_user1->allocate_bridge(algorithm::asset::id_of("XMR"), (uint8_t)kernel::params().policy.participation.min_per_account, 0.005);
		setup_user1->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(setup_user1);

		for (size_t i = 1; i < users.size(); i++)
		{
			auto& [user_n, user_n_nonce] = users[i];
			auto* setup_user_n = memory::init<transactions::setup>();
			setup_user_n->allocate_participation_stake(decimal::zero());
			setup_user_n->sign(user_n.secret_key, user_n_nonce++, decimal::zero()).expect("pre-validation failed");
			transactions.push_back(setup_user_n);
		}
	}
	static void setup_custom(vector<uptr<ledger::transaction_message>>& transactions, vector<account_ref>& users, size_t user_id, int8_t tx_attestation, int8_t mpc_participation)
	{
		auto& [user1, user1_nonce] = users[user_id];
		auto* setup_user1 = memory::init<transactions::setup>();
		if (tx_attestation != 0)
		{
			if (tx_attestation > 0)
			{
				setup_user1->allocate_attestation_stake(algorithm::asset::id_of("ETH"), decimal::zero(), 0);
				setup_user1->allocate_attestation_stake(algorithm::asset::id_of("XRP"), decimal::zero(), 0);
				setup_user1->allocate_attestation_stake(algorithm::asset::id_of("BTC"), decimal::zero(), 0);
			}
			else
			{
				setup_user1->disable_attestation(algorithm::asset::id_of("ETH"));
				setup_user1->disable_attestation(algorithm::asset::id_of("XRP"));
				setup_user1->disable_attestation(algorithm::asset::id_of("BTC"));
			}
		}
		if (mpc_participation != 0)
		{
			if (mpc_participation > 0)
				setup_user1->allocate_participation_stake(decimal::zero());
			else
				setup_user1->disable_participation();
		}
		setup_user1->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(setup_user1);
	}
	static void route_stage_0(vector<uptr<ledger::transaction_message>>& transactions, vector<account_ref>& users)
	{
		auto& [user1, user1_nonce] = users[0];
		auto executor = ledger::executor_context(nullptr);
		auto* route_bitcoin = memory::init<transactions::route>();
		route_bitcoin->set_asset("BTC");
		route_bitcoin->set_routing_address("mmtubFoJvXrBuBUQFf1RrowXUbsiPDYnYS");
		route_bitcoin->set_bridge_hash(executor.get_bridge_instances(route_bitcoin->asset, 0, 1)->front().ref.hash);
		route_bitcoin->solve_pow_challenge(user1.public_key_hash, user1_nonce, 0);
		route_bitcoin->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(route_bitcoin);

		auto* route_ethereum = memory::init<transactions::route>();
		route_ethereum->set_asset("ETH");
		route_ethereum->set_routing_address("0xCa0dfDdBb1cBD7B5A08E9173D9bbE5722138d4d5");
		route_ethereum->set_bridge_hash(executor.get_bridge_instances(route_ethereum->asset, 0, 1)->front().ref.hash);
		route_ethereum->solve_pow_challenge(user1.public_key_hash, user1_nonce, 0);
		route_ethereum->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(route_ethereum);

		auto* route_tron = memory::init<transactions::route>();
		route_tron->set_asset("TRX");
		route_tron->set_routing_address("TFwBey8L5swmhRGEQSCnULT7ad68KFJe6L");
		route_tron->set_bridge_hash(executor.get_bridge_instances(route_tron->asset, 0, 1)->front().ref.hash);
		route_tron->solve_pow_challenge(user1.public_key_hash, user1_nonce, 0);
		route_tron->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(route_tron);
	}
	static void route_stage_1(vector<uptr<ledger::transaction_message>>& transactions, vector<account_ref>& users)
	{
		auto& [user1, user1_nonce] = users[0];
		auto& [user2, user2_nonce] = users[1];
		auto executor = ledger::executor_context(nullptr);
		auto* route_ethereum = memory::init<transactions::route>();
		route_ethereum->set_asset("ETH");
		route_ethereum->set_routing_address("0xCa0dfDdBb1cBD7B5A08E9173D9bbE5722138d4d5");
		route_ethereum->set_bridge_hash(executor.get_bridge_instances(route_ethereum->asset, 0, 1)->front().ref.hash);
		route_ethereum->solve_pow_challenge(user1.public_key_hash, user1_nonce, 0);
		route_ethereum->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(route_ethereum);

		auto* route_ripple = memory::init<transactions::route>();
		route_ripple->set_asset("XRP");
		route_ripple->set_routing_address("rUBqz2JiRCT3gYZBnm28y5ME7e5UpSm2ok");
		route_ripple->set_bridge_hash(executor.get_bridge_instances(route_ripple->asset, 0, 1)->front().ref.hash);
		route_ripple->solve_pow_challenge(user1.public_key_hash, user1_nonce, 0);
		route_ripple->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(route_ripple);

		auto* route_bitcoin = memory::init<transactions::route>();
		route_bitcoin->set_asset("BTC");
		route_bitcoin->set_routing_address("mmtubFoJvXrBuBUQFf1RrowXUbsiPDYnYS");
		route_bitcoin->set_bridge_hash(executor.get_bridge_instances(route_bitcoin->asset, 0, 1)->front().ref.hash);
		route_bitcoin->solve_pow_challenge(user1.public_key_hash, user1_nonce, 0);
		route_bitcoin->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(route_bitcoin);

		auto* route_monero = memory::init<transactions::route>();
		route_monero->set_asset("XMR");
		route_monero->set_routing_address("42prqAvRG2ZfQQ66W9mkgQ2hFbQdeMgmVbJBL1E9o8V5gevzNEcfnBdTS7CUx2PHfjG8WUoQTE9wcawyfPQx1h2z7tCF4hZ");
		route_monero->set_bridge_hash(executor.get_bridge_instances(route_monero->asset, 0, 1)->front().ref.hash);
		route_monero->solve_pow_challenge(user1.public_key_hash, user1_nonce, 0);
		route_monero->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(route_monero);
	}
	static void route_stage_2(vector<uptr<ledger::transaction_message>>& transactions, vector<account_ref>& users)
	{
		auto& [user1, user1_nonce] = users[0];
		auto& [user2, user2_nonce] = users[1];
		auto executor = ledger::executor_context(nullptr);
		uint8_t seed[] = "123456";
		auto* offchain = superchain::bridge::get();
		auto eth_wallet = *offchain->compute_wallet(algorithm::asset::id_of("ETH"), seed, sizeof(seed) - 1);
		auto* route_ethereum_frontrunning = memory::init<transactions::route>();
		route_ethereum_frontrunning->set_asset("ETH");
		route_ethereum_frontrunning->set_routing_address(eth_wallet.encoded_addresses.begin()->second);
		route_ethereum_frontrunning->set_bridge_hash(executor.get_bridge_instances(route_ethereum_frontrunning->asset, 0, 1)->front().ref.hash);
		route_ethereum_frontrunning->solve_pow_challenge(user2.public_key_hash, user2_nonce, 0);
		route_ethereum_frontrunning->sign(user2.secret_key, user2_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(route_ethereum_frontrunning);

		uint8_t hash256[32]; uint256_t hash;
		auto message = transactions::route::as_ownership_challenge(route_ethereum_frontrunning->asset, user1.public_key_hash, eth_wallet.encoded_addresses.begin()->second, user1_nonce);
		keccak_256((uint8_t*)message.data(), message.size(), hash256);
		hash.decode(hash256);

		auto signature = algorithm::hashsig_t();
		auto* chain = offchain->get_network(route_ethereum_frontrunning->asset);
		VI_PANIC(chain && algorithm::signing::sign(hash, algorithm::seckey_t(eth_wallet.secret_key), signature), "failed to sign ownership challenge");

		auto* route_ethereum_transfer = memory::init<transactions::route>();
		route_ethereum_transfer->set_asset("ETH");
		route_ethereum_transfer->set_gas(decimal::zero(), route_ethereum_frontrunning->gas_limit * 2);
		route_ethereum_transfer->set_routing_address(eth_wallet.encoded_addresses.begin()->second);
		route_ethereum_transfer->set_ownership_proof(chain->encode_signature(signature.view()).expect("failed to encode eth signature"), eth_wallet.encoded_public_key);
		route_ethereum_transfer->set_bridge_hash(executor.get_bridge_instances(route_ethereum_frontrunning->asset, 0, 1)->front().ref.hash);
		route_ethereum_transfer->solve_pow_challenge(user1.public_key_hash, user1_nonce, 0);
		VI_PANIC(route_ethereum_transfer->sign(user1.secret_key, user1_nonce++), "tx sign failed");
		transactions.push_back(route_ethereum_transfer);
	}
	static void route_stage_3(vector<uptr<ledger::transaction_message>>& transactions, vector<account_ref>& users)
	{
		auto& [user2, user2_nonce] = users[1];
		auto executor = ledger::executor_context(nullptr);
		auto* route_ethereum = memory::init<transactions::route>();
		route_ethereum->set_asset("ETH");
		route_ethereum->set_routing_address("0x271cae34C9929E4E717eA351e9e494dfbC384b08");
		route_ethereum->set_bridge_hash(executor.get_bridge_instances(route_ethereum->asset, 0, 1)->front().ref.hash);
		route_ethereum->solve_pow_challenge(user2.public_key_hash, user2_nonce, 0);
		route_ethereum->sign(user2.secret_key, user2_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(route_ethereum);

		auto* route_ripple = memory::init<transactions::route>();
		route_ripple->set_asset("XRP");
		route_ripple->set_routing_address("rsLLrqPUXuzuxkwZntnjStvJtH3yMTF2wY");
		route_ripple->set_bridge_hash(executor.get_bridge_instances(route_ripple->asset, 0, 1)->front().ref.hash);
		route_ripple->solve_pow_challenge(user2.public_key_hash, user2_nonce, 0);
		route_ripple->sign(user2.secret_key, user2_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(route_ripple);

		auto* route_bitcoin = memory::init<transactions::route>();
		route_bitcoin->set_asset("BTC");
		route_bitcoin->set_routing_address("bcrt1qvhj97s9lzkpe388l7d6n3vy9ra5cjp8vwrmndc");
		route_bitcoin->set_bridge_hash(executor.get_bridge_instances(route_bitcoin->asset, 0, 1)->front().ref.hash);
		route_bitcoin->solve_pow_challenge(user2.public_key_hash, user2_nonce, 0);
		route_bitcoin->sign(user2.secret_key, user2_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(route_bitcoin);
	}
	static void route_stage_4(vector<uptr<ledger::transaction_message>>& transactions, vector<account_ref>& users)
	{
		auto& [user1, user1_nonce] = users[0];
		auto executor = ledger::executor_context(nullptr);
		auto* route_ethereum = memory::init<transactions::route>();
		route_ethereum->set_asset("ETH");
		route_ethereum->set_bridge_hash(executor.get_bridge_instances(route_ethereum->asset, 0, 1)->front().ref.hash);
		route_ethereum->solve_pow_challenge(user1.public_key_hash, user1_nonce, 0);
		route_ethereum->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(route_ethereum);

		auto* route_ripple = memory::init<transactions::route>();
		route_ripple->set_asset("XLM");
		route_ripple->set_bridge_hash(executor.get_bridge_instances(route_ripple->asset, 0, 1)->front().ref.hash);
		route_ripple->solve_pow_challenge(user1.public_key_hash, user1_nonce, 0);
		route_ripple->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(route_ripple);

		auto* route_bitcoin = memory::init<transactions::route>();
		route_bitcoin->set_asset("BTC");
		route_bitcoin->set_bridge_hash(executor.get_bridge_instances(route_bitcoin->asset, 0, 1)->front().ref.hash);
		route_bitcoin->solve_pow_challenge(user1.public_key_hash, user1_nonce, 0);
		route_bitcoin->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(route_bitcoin);

		auto* route_monero = memory::init<transactions::route>();
		route_monero->set_asset("XMR");
		route_monero->set_bridge_hash(executor.get_bridge_instances(route_monero->asset, 0, 1)->front().ref.hash);
		route_monero->solve_pow_challenge(user1.public_key_hash, user1_nonce, 0);
		route_monero->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(route_monero);
	}
	static void attestate_stage_0(vector<uptr<ledger::transaction_message>>& transactions, vector<account_ref>& users)
	{
		auto& [user1, user1_nonce] = users[0];
		auto executor = ledger::executor_context(nullptr);
		auto owner_addresses = *executor.get_witness_accounts_by_purpose(user1.public_key_hash, states::witness_account::account_type::bridge, 0, 128);
		auto address_bitcoin = std::find_if(owner_addresses.begin(), owner_addresses.end(), [](states::witness_account& item) { return item.ref.asset == algorithm::asset::id_of("BTC"); });
		auto address_ethereum = std::find_if(owner_addresses.begin(), owner_addresses.end(), [](states::witness_account& item) { return item.ref.asset == algorithm::asset::id_of("ETH"); });
		auto address_tron = std::find_if(owner_addresses.begin(), owner_addresses.end(), [](states::witness_account& item) { return item.ref.asset == algorithm::asset::id_of("TRX"); });
		VI_PANIC(address_bitcoin != owner_addresses.end(), "bitcoin bridge address not found");
		VI_PANIC(address_ethereum != owner_addresses.end(), "ethereum bridge address not found");
		VI_PANIC(address_tron != owner_addresses.end(), "tron bridge address not found");

		auto* attestate_bitcoin = memory::init<transactions::attestate>();
		attestate_bitcoin->set_asset("BTC");
		attestate_bitcoin->set_finalized_proof(846982,
			"57638131d9af3033a5e20b753af254e1e8321b2039f16dfd222f6b1117b5c69d",
			{ superchain::value_transfer(attestate_bitcoin->asset, "mmtubFoJvXrBuBUQFf1RrowXUbsiPDYnYS", 12.0) },
			{ superchain::value_transfer(attestate_bitcoin->asset, address_bitcoin->addresses.begin()->second, 12.0) });
		transactions.push_back(attestate_bitcoin);

		auto token_asset = algorithm::asset::id_of("ETH", "USDT", "0xdAC17F958D2ee523a2206206994597C13D831ec7");
		auto* attestate_ethereum = memory::init<transactions::attestate>();
		attestate_ethereum->set_asset("ETH");
		attestate_ethereum->set_finalized_proof(14977180,
			"0x2bc2c98682f1b8fea2031e8f3f56494cd778da9d042da8439fb698d41bf061ea",
			{ superchain::value_transfer(token_asset, "0xCa0dfDdBb1cBD7B5A08E9173D9bbE5722138d4d5", 1000000) },
			{ superchain::value_transfer(token_asset, address_ethereum->addresses.begin()->second, 1000000) });
		transactions.push_back(attestate_ethereum);

		token_asset = algorithm::asset::id_of("ETH", "tBTC", "0x18084fbA666a33d37592fA2633fD49a74DD93a88");
		attestate_ethereum = memory::init<transactions::attestate>();
		attestate_ethereum->set_asset("ETH");
		attestate_ethereum->set_finalized_proof(24147187,
			"0xf3286b2f1e1d8685bd1a41124bab21bd1496a28eee38c6a87a72d6b30f8546e4",
			{ superchain::value_transfer(token_asset, "0xCa0dfDdBb1cBD7B5A08E9173D9bbE5722138d4d5", 12) },
			{ superchain::value_transfer(token_asset, address_ethereum->addresses.begin()->second, 12) });
		transactions.push_back(attestate_ethereum);

		token_asset = algorithm::asset::id_of("TRX", "USDT", "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t");
		auto* attestate_tron = memory::init<transactions::attestate>();
		attestate_tron->set_asset("TRX");
		attestate_tron->set_finalized_proof(78662308,
			"798926719b28355b97b079f540dff72ce8fb246c10323900c07dbbba5866189b",
			{ superchain::value_transfer(token_asset, "TFwBey8L5swmhRGEQSCnULT7ad68KFJe6L", 400000) },
			{ superchain::value_transfer(token_asset, address_tron->addresses.begin()->second, 400000) });
		transactions.push_back(attestate_tron);
	}
	static void attestate_stage_1(vector<uptr<ledger::transaction_message>>& transactions, vector<account_ref>& users)
	{
		auto& [user1, user1_nonce] = users[0];
		auto& [user2, user2_nonce] = users[1];
		auto executor = ledger::executor_context(nullptr);
		auto bridge_instance_ethereum = executor.get_bridge_instances(algorithm::asset::id_of("ETH"), 0, 1)->front();
		auto bridge_instance_ripple = executor.get_bridge_instances(algorithm::asset::id_of("XRP"), 0, 1)->front();
		auto bridge_instance_bitcoin = executor.get_bridge_instances(algorithm::asset::id_of("BTC"), 0, 1)->front();
		auto bridge_instance_monero = executor.get_bridge_instances(algorithm::asset::id_of("XMR"), 0, 1)->front();
		auto owner_addresses = *executor.get_witness_accounts_by_purpose(user1.public_key_hash, states::witness_account::account_type::bridge, 0, 128);
		auto address_ethereum = std::find_if(owner_addresses.begin(), owner_addresses.end(), [&](states::witness_account& item) { return item.ref.hash == bridge_instance_ethereum.ref.hash && item.ref.asset == bridge_instance_ethereum.ref.asset; });
		auto address_ripple = std::find_if(owner_addresses.begin(), owner_addresses.end(), [&](states::witness_account& item) { return item.ref.hash == bridge_instance_ripple.ref.hash && item.ref.asset == bridge_instance_ripple.ref.asset; });
		auto address_bitcoin = std::find_if(owner_addresses.begin(), owner_addresses.end(), [&](states::witness_account& item) { return item.ref.hash == bridge_instance_bitcoin.ref.hash && item.ref.asset == bridge_instance_bitcoin.ref.asset; });
		auto address_monero = std::find_if(owner_addresses.begin(), owner_addresses.end(), [&](states::witness_account& item) { return item.ref.hash == bridge_instance_monero.ref.hash && item.ref.asset == bridge_instance_monero.ref.asset; });
		VI_PANIC(address_ethereum != owner_addresses.end(), "ethereum bridge address not found");
		VI_PANIC(address_ripple != owner_addresses.end(), "ripple bridge address not found");
		VI_PANIC(address_bitcoin != owner_addresses.end(), "bitcoin bridge address not found");
		VI_PANIC(address_monero != owner_addresses.end(), "monero bridge address not found");

		auto token_asset = algorithm::asset::id_of("ETH", "USDT", "0xdAC17F958D2ee523a2206206994597C13D831ec7");
		auto* attestate_ethereum_token = memory::init<transactions::attestate>();
		attestate_ethereum_token->set_asset("ETH");
		attestate_ethereum_token->set_finalized_proof(22946911,
			"0xce2d48c20305ee332c071a671142953af58ca5226fcbcc219cd0b2cc4c6fe34f",
			{ superchain::value_transfer(token_asset, "0xCa0dfDdBb1cBD7B5A08E9173D9bbE5722138d4d5", 100000) },
			{ superchain::value_transfer(token_asset, address_ethereum->addresses.begin()->second, 100000) });
		transactions.push_back(attestate_ethereum_token);

		auto* attestate_ethereum = memory::init<transactions::attestate>();
		attestate_ethereum->set_asset("ETH");
		attestate_ethereum->set_finalized_proof(14977180,
			"0x2bc2c98682f1b8fea2031e8f3f56494cd778da9d042da8439fb698d41bf061ea",
			{ superchain::value_transfer(attestate_ethereum->asset, "0xCa0dfDdBb1cBD7B5A08E9173D9bbE5722138d4d5", 100) },
			{ superchain::value_transfer(attestate_ethereum->asset, address_ethereum->addresses.begin()->second, 100) });
		transactions.push_back(attestate_ethereum);

		auto* attestate_ripple = memory::init<transactions::attestate>();
		attestate_ripple->set_asset("XRP");
		attestate_ripple->set_finalized_proof(88546830,
			"2618D20B801AF96DD060B34228E2594E30AFB7B33E335A8C60199B6CF8B0A69F",
			{ superchain::value_transfer(attestate_ripple->asset, "rUBqz2JiRCT3gYZBnm28y5ME7e5UpSm2ok", 1000) },
			{ superchain::value_transfer(attestate_ripple->asset, address_ripple->addresses.begin()->second, 1000) });
		transactions.push_back(attestate_ripple);

		auto* attestate_bitcoin = memory::init<transactions::attestate>();
		attestate_bitcoin->set_asset("BTC");
		attestate_bitcoin->set_finalized_proof(846982,
			"57638131d9af3033a5e20b753af254e1e8321b2039f16dfd222f6b1117b5c69d",
			{ superchain::value_transfer(attestate_bitcoin->asset, "mmtubFoJvXrBuBUQFf1RrowXUbsiPDYnYS", 1.0) },
			{ superchain::value_transfer(attestate_bitcoin->asset, address_bitcoin->addresses.begin()->second, 1.0) });
		transactions.push_back(attestate_bitcoin);

		auto* attestate_monero = memory::init<transactions::attestate>();
		attestate_monero->set_asset("XMR");
		attestate_monero->set_finalized_proof(3736523,
			"e48546d0fe54eabfc28591325ebfb8175f36fe36eea991a7066837103a66c315",
			{ superchain::value_transfer(attestate_monero->asset, "42prqAvRG2ZfQQ66W9mkgQ2hFbQdeMgmVbJBL1E9o8V5gevzNEcfnBdTS7CUx2PHfjG8WUoQTE9wcawyfPQx1h2z7tCF4hZ", 10.0) },
			{ superchain::value_transfer(attestate_monero->asset, address_monero->addresses.begin()->second, 10.0) });
		transactions.push_back(attestate_monero);
	}
	static void migrate_stage_1(vector<uptr<ledger::transaction_message>>& transactions, vector<account_ref>& users)
	{
		auto& [user1, user1_nonce] = users[0];
		auto& [user2, user2_nonce] = users[1];
		auto executor = ledger::executor_context(nullptr);
		auto* withdrawal_ethereum_token = memory::init<transactions::withdraw>();
		withdrawal_ethereum_token->set_asset("ETH", "USDT", "0xdAC17F958D2ee523a2206206994597C13D831ec7");
		withdrawal_ethereum_token->set_routing_target(delegations::broadcast_delegation::mockup_target_broadcast_error(), 1);
		withdrawal_ethereum_token->set_bridge_hash(executor.get_bridge_instances(withdrawal_ethereum_token->asset, 0, 1)->front().ref.hash);
		withdrawal_ethereum_token->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(withdrawal_ethereum_token);
	}
	static void migrate_stage_2(vector<uptr<ledger::transaction_message>>& transactions, vector<account_ref>& users)
	{
		size_t users_starting_count = users.size();
		size_t users_ending_count = users_starting_count + kernel::params().policy.participation.max_per_account;
		for (size_t i = users_starting_count; i < users_ending_count; i++)
		{
			users.push_back(account_ref(ledger::wallet::from_seed(stringify::text("00000%i", (int)i)), 0));
			auto& [user_n, user_n_nonce] = users[i];
			auto* setup_user_n = memory::init<transactions::setup>();
			setup_user_n->allocate_participation_stake(decimal::zero());
			setup_user_n->sign(user_n.secret_key, user_n_nonce++, decimal::zero()).expect("pre-validation failed");
			transactions.push_back(setup_user_n);
		}
	}
	static void migrate_stage_3(vector<uptr<ledger::transaction_message>>& transactions, vector<account_ref>& users)
	{
		auto& [user2, user2_nonce] = users[1];
		auto* setup_user2 = memory::init<transactions::setup>();
		setup_user2->disable_participation();
		setup_user2->sign(user2.secret_key, user2_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(setup_user2);
	}
	static void migrate_stage_4(vector<uptr<ledger::transaction_message>>& transactions, vector<account_ref>& users)
	{
		auto chain = storages::chainstate();
		auto block_number = chain.get_latest_block_number().expect("must have parent block") - 3;
		auto targets = chain.get_block_transactions_by_number(block_number, 0, 1).expect("block " + to_string(block_number) + " must have a transaction");
		VI_PANIC(!targets.empty(), "must have last transaction");

		auto& broadcast_transaction_ptr = targets.front().transaction;
		VI_PANIC(broadcast_transaction_ptr->as_type() == transactions::broadcast::as_instance_type(), "must have withdrawal finalization as last transaction");

		auto* broadcast_transaction = (transactions::broadcast*)*broadcast_transaction_ptr;
		VI_PANIC(!broadcast_transaction->proof, "withdrawal must be failed (synthetic fault error)");

		auto& [user2, user2_nonce] = users[1];
		auto executor = ledger::executor_context(nullptr);
		auto withdraw_transaction_ptr = executor.get_block_transaction<transactions::withdraw>(broadcast_transaction->withdraw_hash);
		VI_PANIC(withdraw_transaction_ptr, "withdraw transaction must be present");

		auto* withdraw_transaction = (transactions::withdraw*)*withdraw_transaction_ptr->transaction;
		auto accounts = executor.get_bridge_accounts(withdraw_transaction->bridge_hash, 0, 128).expect("user 2 must have bridge accounts");
		VI_PANIC(!accounts.empty(), "bridge instance must have at least one bridge account under management corresponding to failed withdrawal");
		
		auto participant = algorithm::pubkeyhash_t();
		auto message = broadcast_transaction->proof.error().message();
		auto address = message.substr(1, message.find(')') - 1);
		VI_PANIC(algorithm::signing::decode_address(address, participant), "failed to decode the migration participant");

		auto* setup_user2 = memory::init<transactions::setup>();
		setup_user2->migrate_participant(broadcast_transaction->as_hash(), participant);
		setup_user2->sign(user2.secret_key, user2_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(setup_user2);
	}
	static void withdraw_stage_1(vector<uptr<ledger::transaction_message>>& transactions, vector<account_ref>& users)
	{
		auto& [user1, user1_nonce] = users[0];
		auto& [user2, user2_nonce] = users[1];
		auto executor = ledger::executor_context(nullptr);
		auto* withdrawal_ethereum_token = memory::init<transactions::withdraw>();
		withdrawal_ethereum_token->set_asset("ETH", "USDT", "0xdAC17F958D2ee523a2206206994597C13D831ec7");
		withdrawal_ethereum_token->set_routing_target(delegations::broadcast_delegation::mockup_target_attestate_error(), executor.get_account_balance(algorithm::asset::id_of("ETH", "USDT", "0xdAC17F958D2ee523a2206206994597C13D831ec7"), user1.public_key_hash).expect("user balance not valid").get_balance());
		withdrawal_ethereum_token->set_bridge_hash(executor.get_bridge_instances(withdrawal_ethereum_token->asset, 0, 1)->front().ref.hash);
		withdrawal_ethereum_token->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(withdrawal_ethereum_token);
	}
	static void withdraw_stage_2(vector<uptr<ledger::transaction_message>>& transactions, vector<account_ref>& users)
	{
		auto& [user1, user1_nonce] = users[0];
		auto& [user2, user2_nonce] = users[1];
		auto executor = ledger::executor_context(nullptr);
		auto* withdrawal_ethereum_token = memory::init<transactions::withdraw>();
		withdrawal_ethereum_token->set_asset("ETH", "USDT", "0xdAC17F958D2ee523a2206206994597C13D831ec7");
		withdrawal_ethereum_token->set_routing_target(delegations::broadcast_delegation::mockup_target_attestate_absent(), executor.get_account_balance(algorithm::asset::id_of("ETH", "USDT", "0xdAC17F958D2ee523a2206206994597C13D831ec7"), user1.public_key_hash).expect("user balance not valid").get_balance());
		withdrawal_ethereum_token->set_bridge_hash(executor.get_bridge_instances(withdrawal_ethereum_token->asset, 0, 1)->front().ref.hash);
		withdrawal_ethereum_token->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(withdrawal_ethereum_token);
	}
	static void withdraw_stage_3(vector<uptr<ledger::transaction_message>>& transactions, vector<account_ref>& users)
	{
		auto& [user1, user1_nonce] = users[0];
		auto& [user2, user2_nonce] = users[1];
		auto* transfer_ripple = memory::init<transactions::transfer>();
		transfer_ripple->set_asset("XRP");
		transfer_ripple->set_to(user2.public_key_hash, 1.0);
		transfer_ripple->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(transfer_ripple);
	}
	static void withdraw_stage_4(vector<uptr<ledger::transaction_message>>& transactions, vector<account_ref>& users)
	{
		auto& [user1, user1_nonce] = users[0];
		auto& [user2, user2_nonce] = users[1];
		auto* transfer_ripple = memory::init<transactions::transfer>();
		transfer_ripple->set_asset("XRP");
		transfer_ripple->set_to(user1.public_key_hash, 1.0);
		transfer_ripple->sign(user2.secret_key, user2_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(transfer_ripple);
	}
	static void withdraw_stage_5(vector<uptr<ledger::transaction_message>>& transactions, vector<account_ref>& users)
	{
		auto chain = storages::chainstate();
		auto block_number = chain.get_latest_block_number().expect("must have parent block") - 2;
		auto targets = chain.get_block_transactions_by_number(block_number, 0, 1).expect("block " + to_string(block_number) + " must have a transaction");
		VI_PANIC(!targets.empty(), "must have last transaction");

		auto& broadcast_transaction_ptr = targets.front().transaction;
		VI_PANIC(broadcast_transaction_ptr->as_type() == transactions::broadcast::as_instance_type(), "must have withdrawal finalization as last transaction");

		auto* broadcast_transaction = (transactions::broadcast*)*broadcast_transaction_ptr;
		VI_PANIC(broadcast_transaction->proof && broadcast_transaction->proof->prepared.outputs.size() == 1 && broadcast_transaction->proof->prepared.outputs.front().link.address == delegations::broadcast_delegation::mockup_target_attestate_absent(), "withdrawal must be finalized (synthetic missing error)");

		auto& [user1, user1_nonce] = users[0];
		auto* anticast_ethereum_token = memory::init<transactions::anticast>();
		anticast_ethereum_token->asset = broadcast_transaction->asset;
		anticast_ethereum_token->set_protest(broadcast_transaction->as_hash());
		anticast_ethereum_token->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(anticast_ethereum_token);
	}
	static void withdraw_stage_6(vector<uptr<ledger::transaction_message>>& transactions, vector<account_ref>& users)
	{
		auto& [user1, user1_nonce] = users[0];
		auto& [user2, user2_nonce] = users[1];
		auto executor = ledger::executor_context(nullptr);
		auto* withdrawal_ethereum_token = memory::init<transactions::withdraw>();
		withdrawal_ethereum_token->set_asset("ETH", "USDT", "0xdAC17F958D2ee523a2206206994597C13D831ec7");
		withdrawal_ethereum_token->set_routing_target("0xCa0dfDdBb1cBD7B5A08E9173D9bbE5722138d4d5", executor.get_account_balance(algorithm::asset::id_of("ETH", "USDT", "0xdAC17F958D2ee523a2206206994597C13D831ec7"), user1.public_key_hash).expect("user balance not valid").get_balance());
		withdrawal_ethereum_token->set_bridge_hash(executor.get_bridge_instances(withdrawal_ethereum_token->asset, 0, 1)->front().ref.hash);
		withdrawal_ethereum_token->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(withdrawal_ethereum_token);
	}
	static void withdraw_stage_7(vector<uptr<ledger::transaction_message>>& transactions, vector<account_ref>& users)
	{
		auto& [user1, user1_nonce] = users[0];
		auto& [user2, user2_nonce] = users[1];
		auto executor = ledger::executor_context(nullptr);
		auto bridge_ethereum = executor.get_bridge_instances(algorithm::asset::id_of("ETH"), 0, 1)->front();
		auto* withdrawal_ethereum = memory::init<transactions::withdraw>();
		withdrawal_ethereum->set_asset("ETH");
		withdrawal_ethereum->set_routing_target("0xCa0dfDdBb1cBD7B5A08E9173D9bbE5722138d4d5", executor.get_account_balance(algorithm::asset::id_of("ETH"), user1.public_key_hash).expect("user balance not valid").get_balance() - bridge_ethereum.fee_rate);
		withdrawal_ethereum->set_bridge_hash(executor.get_bridge_instances(withdrawal_ethereum->asset, 0, 1)->front().ref.hash);
		withdrawal_ethereum->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(withdrawal_ethereum);

		auto bridge_ripple = executor.get_bridge_instances(algorithm::asset::id_of("XRP"), 0, 1)->front();
		auto* withdrawal_ripple = memory::init<transactions::withdraw>();
		withdrawal_ripple->set_asset("XRP");
		withdrawal_ripple->set_routing_target("rUBqz2JiRCT3gYZBnm28y5ME7e5UpSm2ok", executor.get_account_balance(algorithm::asset::id_of("XRP"), user1.public_key_hash).expect("user balance not valid").get_balance() - bridge_ripple.fee_rate);
		withdrawal_ripple->set_bridge_hash(executor.get_bridge_instances(withdrawal_ripple->asset, 0, 1)->front().ref.hash);
		withdrawal_ripple->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(withdrawal_ripple);

		auto bridge_bitcoin = executor.get_bridge_instances(algorithm::asset::id_of("BTC"), 0, 1)->front();
		auto* withdrawal_bitcoin = memory::init<transactions::withdraw>();
		withdrawal_bitcoin->set_asset("BTC");
		withdrawal_bitcoin->set_routing_target("mmtubFoJvXrBuBUQFf1RrowXUbsiPDYnYS", executor.get_account_balance(algorithm::asset::id_of("BTC"), user1.public_key_hash).expect("user balance not valid").get_balance() - bridge_bitcoin.fee_rate);
		withdrawal_bitcoin->set_bridge_hash(executor.get_bridge_instances(withdrawal_bitcoin->asset, 0, 1)->front().ref.hash);
		withdrawal_bitcoin->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(withdrawal_bitcoin);

		auto bridge_monero = executor.get_bridge_instances(algorithm::asset::id_of("XMR"), 0, 1)->front();
		auto* withdrawal_monero = memory::init<transactions::withdraw>();
		withdrawal_monero->set_asset("XMR");
		withdrawal_monero->set_routing_target("42prqAvRG2ZfQQ66W9mkgQ2hFbQdeMgmVbJBL1E9o8V5gevzNEcfnBdTS7CUx2PHfjG8WUoQTE9wcawyfPQx1h2z7tCF4hZ", executor.get_account_balance(algorithm::asset::id_of("BTC"), user1.public_key_hash).expect("user balance not valid").get_balance() - bridge_monero.fee_rate);
		withdrawal_monero->set_bridge_hash(executor.get_bridge_instances(withdrawal_monero->asset, 0, 1)->front().ref.hash);
		withdrawal_monero->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(withdrawal_monero);
	}
	static void withdraw_stage_8(vector<uptr<ledger::transaction_message>>& transactions, vector<account_ref>& users)
	{
		auto& [user1, user1_nonce] = users[0];
		auto& [user2, user2_nonce] = users[1];
		auto executor = ledger::executor_context(nullptr);
		auto bridge_ethereum = executor.get_bridge_instances(algorithm::asset::id_of("ETH"), 0, 1)->front();
		auto* withdrawal_ethereum = memory::init<transactions::withdraw>();
		withdrawal_ethereum->set_asset("ETH");
		withdrawal_ethereum->set_routing_target("0x89a0181659bd280836A2d33F57e3B5Dfa1a823CE", executor.get_account_balance(algorithm::asset::id_of("ETH"), user2.public_key_hash).expect("user balance not valid").get_balance() - bridge_ethereum.fee_rate);
		withdrawal_ethereum->set_bridge_hash(executor.get_bridge_instances(withdrawal_ethereum->asset, 0, 1)->front().ref.hash);
		withdrawal_ethereum->sign(user2.secret_key, user2_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(withdrawal_ethereum);

		auto bridge_ripple = executor.get_bridge_instances(algorithm::asset::id_of("XRP"), 0, 1)->front();
		auto* withdrawal_ripple = memory::init<transactions::withdraw>();
		withdrawal_ripple->set_asset("XRP");
		withdrawal_ripple->set_routing_target("rJGb4etn9GSwNHYVu7dNMbdiVgzqxaTSUG", executor.get_account_balance(algorithm::asset::id_of("XRP"), user2.public_key_hash).expect("user balance not valid").get_balance() - bridge_ripple.fee_rate);
		withdrawal_ripple->set_bridge_hash(executor.get_bridge_instances(withdrawal_ripple->asset, 0, 1)->front().ref.hash);
		withdrawal_ripple->sign(user2.secret_key, user2_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(withdrawal_ripple);

		auto bridge_bitcoin = executor.get_bridge_instances(algorithm::asset::id_of("BTC"), 0, 1)->front();
		auto* withdrawal_bitcoin = memory::init<transactions::withdraw>();
		withdrawal_bitcoin->set_asset("BTC");
		withdrawal_bitcoin->set_routing_target("bcrt1p2w7gkghj7arrjy4c45kh7450458hr8dv9pu9576lx08uuh4je7eqgskm9v", executor.get_account_balance(algorithm::asset::id_of("BTC"), user2.public_key_hash).expect("user balance not valid").get_balance() - bridge_bitcoin.fee_rate);
		withdrawal_bitcoin->set_bridge_hash(executor.get_bridge_instances(withdrawal_bitcoin->asset, 0, 1)->front().ref.hash);
		withdrawal_bitcoin->sign(user2.secret_key, user2_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(withdrawal_bitcoin);
	}
	static void production_stage_1(vector<uptr<ledger::transaction_message>>& transactions, vector<account_ref>& users)
	{
		auto& [user2, user2_nonce] = users[1];
		auto* setup_user2 = memory::init<transactions::setup>();
		setup_user2->allocate_production_stake(decimal::zero());
		setup_user2->sign(user2.secret_key, user2_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(setup_user2);
	}
	static void production_stage_2(vector<uptr<ledger::transaction_message>>& transactions, vector<account_ref>& users)
	{
		auto& [user1, user1_nonce] = users[0];
		auto& [user2, user2_nonce] = users[1];
		auto* setup_user1 = memory::init<transactions::setup>();
		setup_user1->allocate_production_stake(decimal::zero());
		setup_user1->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(setup_user1);

		auto* setup_user2 = memory::init<transactions::setup>();
		setup_user2->disable_production();
		setup_user2->sign(user2.secret_key, user2_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(setup_user2);
	}
};

struct tests
{
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
		format::tree data = format::tree::map();
		algorithm::pubkeyhash_t owner;
		algorithm::hashing::hash160((uint8_t*)"publickeyhash", 13, owner.blob);
		uint256_t asset = algorithm::asset::id_of("BTC");
		uint64_t block_number = 1;

		tester::new_serialization_comparison<superchain::wallet_link>(data);
		tester::new_serialization_comparison<superchain::coin_utxo>(data);
		tester::new_serialization_comparison<superchain::computed_transaction>(data);
		tester::new_serialization_comparison<superchain::prepared_transaction>(data);
		tester::new_serialization_comparison<superchain::finalized_transaction>(data);
		tester::new_serialization_comparison<ledger::transaction_receipt>(data);
		tester::new_serialization_comparison<ledger::wallet>(data);
		tester::new_serialization_comparison<ledger::node>(data);
		tester::new_serialization_comparison<ledger::block_transaction>(data);
		tester::new_serialization_comparison<ledger::block_header>(data);
		tester::new_serialization_comparison<ledger::block_body>(data);
		tester::new_serialization_comparison<ledger::block_proof>(data);
		tester::new_serialization_comparison<states::account_nonce>(data, owner, block_number++);
		tester::new_serialization_comparison<states::account_program>(data, owner, block_number++);
		tester::new_serialization_comparison<states::account_uniform>(data, owner, std::string_view(), block_number++);
		tester::new_serialization_comparison<states::account_multiform>(data, owner, std::string_view(), std::string_view(), block_number++);
		tester::new_serialization_comparison<states::account_balance>(data, owner, asset, block_number++);
		tester::new_serialization_comparison<states::validator_production>(data, owner, block_number++);
		tester::new_serialization_comparison<states::validator_production_reward>(data, owner, asset, block_number++);
		tester::new_serialization_comparison<states::validator_participation>(data, owner, block_number++);
		tester::new_serialization_comparison<states::validator_participation_reward>(data, owner, asset, block_number++);
		tester::new_serialization_comparison<states::validator_participation_ref>(data, owner, states::bridge_ref(), block_number++);
		tester::new_serialization_comparison<states::validator_attestation>(data, owner, asset, block_number++);
		tester::new_serialization_comparison<states::validator_attestation_reward>(data, owner, asset, block_number++);
		tester::new_serialization_comparison<states::bridge_instance>(data, states::bridge_ref(), block_number++);
		tester::new_serialization_comparison<states::bridge_balance>(data, asset, 0, block_number++);
		tester::new_serialization_comparison<states::bridge_account>(data, states::bridge_ref(), block_number++);
		tester::new_serialization_comparison<states::witness_program>(data, std::string_view(), block_number++);
		tester::new_serialization_comparison<states::witness_event>(data, asset, block_number++);
		tester::new_serialization_comparison<states::witness_account>(data, states::bridge_ref(), address_map(), block_number++);
		tester::new_serialization_comparison<states::witness_transaction>(data, asset, std::string_view(), block_number++);
		tester::new_serialization_comparison<transactions::transfer>(data);
		tester::new_serialization_comparison<transactions::deploy>(data);
		tester::new_serialization_comparison<transactions::call>(data);
		tester::new_serialization_comparison<transactions::rollup>(data);
		tester::new_serialization_comparison<transactions::route>(data);
		tester::new_serialization_comparison<transactions::bind>(data);
		tester::new_serialization_comparison<transactions::imbind>(data);
		tester::new_serialization_comparison<transactions::setup>(data);
		tester::new_serialization_comparison<transactions::rebind>(data);
		tester::new_serialization_comparison<transactions::withdraw>(data);
		tester::new_serialization_comparison<transactions::broadcast>(data);
		tester::new_serialization_comparison<transactions::attestate>(data);

		auto* term = console::get();
		term->write_line(data.as_json(true));
	}
	/* prove and verify one light proof of work based on 256bit hash function */
	static void cryptography_pow256()
	{
		auto* term = console::get();
		uint256_t block_hash = algorithm::hashing::hash256i("pow challenge");
		uint64_t account_nonce = (block_hash / 2) % 8;
		auto wallet = ledger::wallet::from_seed(block_hash.to_string());
		auto evaluation_time_point = date_time();
		auto solution = algorithm::pow256::solve(block_hash, wallet.public_key_hash, account_nonce);
		auto evaluation_time = evaluation_time_point.elapsed();
		auto verification_time_point = date_time();
		bool proven = algorithm::pow256::verify(block_hash, wallet.public_key_hash, account_nonce, solution);
		auto verification_time = verification_time_point.elapsed();

		auto target = format::tree::map();
		target.set("account", algorithm::signing::serialize_address(wallet.public_key_hash));
		target.set("account_nonce", algorithm::encoding::serialize_uint256(account_nonce));
		target.set("block_hash", format::variable(algorithm::encoding::encode_0xhex256(block_hash)));
		target.set("target_hash", format::variable(algorithm::encoding::encode_0xhex256(algorithm::pow256::target())));
		target.set("solution_nonce", algorithm::encoding::serialize_uint256(solution));
		target.set("solution_time", format::variable((uint64_t)evaluation_time.milliseconds()));
		target.set("verification_time", format::variable((uint64_t)verification_time.milliseconds()));
		target.set("sps", format::variable(decimal(1000.0 / (double)evaluation_time.milliseconds())));
		term->write_line(target.as_json(true));
		VI_PANIC(proven, "pow256 solution is not valid");
	}
	/* prove and verify multiple (nearly) linearly more complex wesolowski vdf signatures */
	static void cryptography_wesolowski()
	{
		auto* term = console::get();
		auto message = "Hello, world!";
		auto data = format::tree::list();
		auto prove_and_verify = [&](uint64_t difficulty)
		{
			auto evaluation_time_point = date_time();
			auto proof = algorithm::wesolowski::evaluate(0, difficulty, message);

			auto evaluation_time = evaluation_time_point.elapsed();
			auto verification_time_point = date_time();
			bool proven = algorithm::wesolowski::verify(0, difficulty, message, proof);

			auto message_copy = string(message);
			message_copy.back() = '?';
			bool not_forged = !algorithm::wesolowski::verify(0, difficulty, message_copy, proof);

			auto verification_time = verification_time_point.elapsed();
			auto* target = data.push(format::tree::map());
			target->set("proof", algorithm::wesolowski::serialize(difficulty, proof));
			target->set("evaluation_time", format::variable((uint64_t)evaluation_time.milliseconds()));
			target->set("verification_time", format::variable((uint64_t)verification_time.milliseconds()));
			if (!proven)
				term->write_line(data.as_json(true));
			VI_PANIC(proven, "wesolowki proof is not valid");
			VI_PANIC(not_forged, "wesolowki proof is forged");
		};

		uint64_t baseline = kernel::params().policy.pow.difficulty;
		prove_and_verify(baseline);
		for (uint64_t i = 3; i < 7; i++)
			prove_and_verify(baseline * (2ll << i));
		term->write_line(data.as_json(true));
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

		auto info = format::tree::map();
		info.set("mnemonic", format::variable(mnemonic));
		info.set("secret_key", format::variable(encoded_secret_key));
		info.set("public_key", format::variable(encoded_public_key));
		info.set("address", format::variable(encoded_public_key_hash));
		info.set("message", format::variable(message));
		info.set("message_hash", format::variable(encoded_message_hash));
		info.set("signature", format::variable(encoded_message_signature));
		info.set("recover_public_key", format::variable(encoded_recover_public_key));
		info.set("recover_address", format::variable(encoded_recover_public_key_hash));
		term->write_line(info.as_json(true));

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
		term->write_line(wallet.as_tree().as_json(true));

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

		format::tree data = format::tree::map();
		auto* user1_wallet_data = (format::tree*)data.set("user1_wallet", user1.as_tree());
		auto* user1_wallet_message_data = user1_wallet_data->set("message", format::tree::map());
		user1_wallet_message_data->set("ciphertext_to_user2_wallet", format::variable(format::util::encode_0xhex(ciphertext1)));
		user1_wallet_message_data->set("plaintext_from_user2_wallet", format::variable(plaintext2));
		auto* user2_wallet_data = (format::tree*)data.set("user2_wallet", user2.as_tree());
		auto* user2_wallet_message_data = user2_wallet_data->set("message", format::tree::map());
		user2_wallet_message_data->set("ciphertext_to_user2_wallet", format::variable(format::util::encode_0xhex(ciphertext2)));
		user2_wallet_message_data->set("plaintext_from_user2_wallet", format::variable(plaintext1));
		term->write_line(data.as_json(true));
	}
	/* transaction cryptography */
	static void cryptography_transaction()
	{
		auto* term = console::get();
		auto wallet = ledger::wallet::from_seed();
		vector<uptr<ledger::transaction_message>> transactions;
		vector<account_ref> users =
		{
			account_ref(wallet, 1),
			account_ref(ledger::wallet::from_seed(), 1)
		};

		auto tx = transactions::transfer();
		tx.gas_limit = ledger::block_body::get_gas_limit();
		tx.set_to(users[1].wallet.public_key_hash, decimal("13.539899"));
		VI_PANIC(tx.sign(users[0].wallet.secret_key, users[0].nonce++), "authentication failed");

		auto tx_blob = tx.as_message().data;
		auto tx_body = format::ro_stream(tx_blob);
		auto tx_copy = uptr<ledger::transaction_message>(transactions::resolver::from_stream(tx_body));
		auto tx_info = tx.as_tree();
		algorithm::pubkeyhash_t recover_public_key_hash;
		tx_info.set("raw_data", format::variable(format::util::encode_0xhex(tx_blob)));

		auto stream = tx.as_message();
		auto reader = stream.ro();
		format::variables vars;
		format::variables_util::deserialize_flat_from(reader, &vars);
		tx_info.set("var_data", format::variables_util::serialize(vars));
		tx_info.set("asset_id", algorithm::asset::serialize(algorithm::asset::id_of("ETH", "USDT", "0xdAC17F958D2ee523a2206206994597C13D831ec7")));
		term->write_line(tx_info.as_json(true));

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
	/* superchain wallets cryptography */
	static void cryptography_multichain_wallet()
	{
		auto* term = console::get();
		auto* offchain = superchain::bridge::get();
		auto user = ledger::wallet::from_seed("0000000");
		for (auto& asset : offchain->get_assets())
		{
			uint8_t seed[] = "123456";
			auto wallet = *offchain->compute_wallet(asset, seed, sizeof(seed) - 1);
			auto info = wallet.as_secret_tree();
			info.set("asset", algorithm::asset::serialize(asset));
			term->write_line(info.as_json(true));
		}
	}
	/* multi-party wallet keypair and signature generation */
	static void cryptography_multichain_mpc()
	{
		auto* term = console::get();
		vector<participant_ref> participants;
		participants.resize(kernel::params().policy.participation.min_per_account);

		auto algorithms =
		{
			std::make_pair(algorithm::composition::type::ed25519, std::string_view("ed25519")),
			std::make_pair(algorithm::composition::type::ed25519_clsag, std::string_view("ed25519_clsag")),
			std::make_pair(algorithm::composition::type::secp256k1, std::string_view("secp256k1")),
			std::make_pair(algorithm::composition::type::secp256k1_schnorr, std::string_view("secp256k1_schnorr"))
		};
		for (auto& [alg, alg_name] : algorithms)
		{
			auto mpc_data = format::tree::map();
			for (size_t i = 0; i < participants.size(); i++)
			{
				auto& share = participants[i];
				auto entropy = "seed" + to_string(i);
				algorithm::hashing::hash512((uint8_t*)entropy.data(), entropy.size(), share.seed.blob);
				share.keypair = algorithm::composition::derive_keypair(alg, share.seed.blob, share.seed.size()).expect("failed to derive a keypair share");

				auto participant_data = mpc_data.set("participant" + to_string(i + 1), format::tree::map());
				participant_data->set("seed", format::variable(format::util::encode_0xhex(share.seed.view())));
				participant_data->set("secret_key", format::variable(format::util::encode_0xhex(std::string_view((char*)share.keypair.secret_key.data(), share.keypair.secret_key.size()))));
				participant_data->set("public_key", format::variable(format::util::encode_0xhex(std::string_view((char*)share.keypair.public_key.data(), share.keypair.public_key.size()))));
			}

			uint8_t message_hash[32];
			std::string_view message = "Hello, World!";
			algorithm::hashing::hash256((uint8_t*)message.data(), message.size(), message_hash);

			uint64_t mpc_state_time = 0;
			size_t mpc_steps = 0;
			size_t mpc_state_bandwidth = 0;
			auto mpc_phase_participants = vector<participant_ref>();
			auto mpc_timeline = vector<string>();
			auto mpc_state = algorithm::composition::make_public_key_compositor(alg, message_hash, sizeof(message_hash), (uint16_t)participants.size()).expect("failed to make the state");
			while (true)
			{
				auto time = date_time();
				auto next = mpc_phase_participants.begin();
				switch (mpc_state->next_phase())
				{
					case algorithm::composition::phase::consume_after_reset:
						mpc_phase_participants = participants;
						next = mpc_phase_participants.begin();
						if (!mpc_timeline.empty())
							mpc_timeline.push_back(stringify::text("advance(%i)", (int)participants.size()));
						[[fallthrough]];
					case algorithm::composition::phase::consume:
						mpc_timeline.push_back(stringify::text("aggregate(%.9s...)", format::util::encode_0xhex(std::string_view((char*)next->keypair.public_key.data(), next->keypair.public_key.size())).c_str()));
						break;
					case algorithm::composition::phase::finalize:
						mpc_timeline.push_back(stringify::text("finalize(%i)", (int)participants.size()));
						break;
					default:
						VI_PANIC(false, "invalid phase");
						break;
				}
				if (next == mpc_phase_participants.end())
					break;

				format::wo_stream message;
				VI_PANIC(mpc_state->store(&message), "failed to store the state");

				auto reader = message.ro();
				auto mpc_state_transition = algorithm::composition::make_compositor_from_stream(alg, reader).expect("failed to load the state");
				mpc_state_transition->aggregate(next->keypair.secret_key).expect("failed to aggregate the state");
				mpc_phase_participants.erase(next);

				VI_PANIC(mpc_state->may_transition_to(**mpc_state_transition), "state machine transition rejected");
				mpc_state = std::move(mpc_state_transition);

				format::wo_stream updated_message;
				VI_PANIC(mpc_state->store(&updated_message), "failed to store the state");
				mpc_state_bandwidth += message.data.size() + updated_message.data.size();
				mpc_state_time += date_time().nanoseconds() - time.nanoseconds();
				++mpc_steps;
			}

			algorithm::composition::cpubkey_t mpc_public_key;
			algorithm::composition::chashsig_t mpc_signature;
			mpc_state->derive_public_key(&mpc_public_key).expect("failed to extract public key from state");
			mpc_state->derive_signature(&mpc_signature).expect("failed to extract signature from state");

			auto* aggregation_data = mpc_data.set("aggregation", format::tree::map());
			auto* aggregation_timeline_data = aggregation_data->set("timeline", format::tree::list());
			for (auto& item : mpc_timeline)
				aggregation_timeline_data->push(format::variable(item));
			aggregation_data->set("public_key", format::variable(format::util::encode_0xhex(std::string_view((char*)mpc_public_key.data(), mpc_public_key.size()))));
			aggregation_data->set("signature", format::variable(format::util::encode_0xhex(std::string_view((char*)mpc_signature.data(), mpc_signature.size()))));
			aggregation_data->set("network_bytes_required", format::variable(mpc_state_bandwidth));
			aggregation_data->set("network_round_trips", format::variable(mpc_steps));
			aggregation_data->set("step_time_ns", format::variable(mpc_steps > 0 ? mpc_state_time / mpc_steps : 0));
			aggregation_data->set("total_time_ms", format::variable(mpc_state_time / 1'000'000));

			mpc_data.set("message", format::variable(message));
			mpc_data.set("message_hash", format::variable(format::util::encode_0xhex(std::string_view((char*)message_hash, sizeof(message_hash)))));
			mpc_data.set("algorithm", format::variable(alg_name));
			mpc_data.set("participants", format::variable(participants.size()));
			term->write_line(mpc_data.as_json(true));
		}
	}
	/* superchain transaction generation test */
	static void cryptography_multichain_transaction()
	{
		auto* offchain = superchain::bridge::get();
		auto* term = console::get();
		auto seed = uint256_t(123456);
		auto create_wallet = [&](const algorithm::asset_id& asset) -> superchain::computed_wallet
		{
			uint8_t seed_buffer[32];
			seed.encode(seed_buffer);

			auto wallet = *offchain->compute_wallet(asset, seed_buffer, sizeof(seed_buffer));
			for (auto& encoded_address : wallet.encoded_addresses)
				offchain->enable_link(asset, superchain::wallet_link(seed, wallet.encoded_public_key, encoded_address.second)).expect("link activation error");
			return wallet;
		};
		auto validate_transaction = [&](const algorithm::asset_id& asset, const superchain::computed_wallet& wallet, superchain::prepared_transaction& prepared, const std::string_view& feature, const std::string_view& expected_calldata)
		{
		recompute:
			auto shared = prepared.as_shared_message();
			auto keygen = shared && shared->keys.empty();
			for (auto& input : prepared.inputs)
			{
				auto state = algorithm::composition::make_signature_compositor(input.alg, input.public_key, input.message.data(), input.message.size(), shared.address(), 1).expect("state initialization error");
				while (state->next_phase() != algorithm::composition::phase::finalize)
					state->aggregate(wallet.secret_key).expect("signature aggregation error");
				state->derive_signature(&input.signature);
				if (shared)
					shared->keys.push_back(input.signature);
			}
			if (keygen && !shared->keys.empty())
			{
				prepared.requires_shared_message(*shared);
				goto recompute;
			}

			superchain::finalized_transaction finalized = offchain->finalize_transaction(asset, std::move(prepared)).expect("prepared transaction finalization error");
			VI_PANIC(finalized.calldata == expected_calldata, "resulting calldata differs from expected calldata");
			term->fwrite_line("%s (%.*s) = %s", algorithm::asset::handle_of(asset).c_str(), (int)feature.size(), feature.data(), finalized.calldata.c_str());
		};
		tester::use_clean_state([&]()
		{
			auto asset = algorithm::asset::id_of("BTC");
			auto state = storages::superchainstate(asset);
			auto* unit = (superchain::translations::bitcoin*)offchain->get_network(asset);
			if (unit != nullptr)
				unit->all_address_types = true;

			auto wallet = create_wallet(asset);
			auto input_p2pkh_hash = codec::hex_decode("0x57e30b41a6d984cdb763145f32ad9678a9b2bfd0267e12d5d0474e97f7d077d0");
			superchain::coin_utxo input_p2pkh;
			input_p2pkh.link = superchain::wallet_link(seed, wallet.encoded_public_key, wallet.encoded_addresses[3]);
			input_p2pkh.transaction_id = "382940bfc9a1fe1f09a3fb8e1fda1b25b90dc2019ff5973b1d9d616e15b29840";
			input_p2pkh.index = 1;
			input_p2pkh.value = 0.1;

			auto input_p2sh_hash = codec::hex_decode("0xc4e23865424498b4d90c57dda4bea4718e1e6ed669cc00796afd864ac6de3606");
			superchain::coin_utxo input_p2sh;
			input_p2sh.link = superchain::wallet_link(seed, wallet.encoded_public_key, wallet.encoded_addresses[2]);
			input_p2sh.transaction_id = "3d7c1f8e03a73821517d2f0220fe3ecf82c2f55b94b724e5d5298c87070802a0";
			input_p2sh.value = 0.1;

			auto input_p2wpkh_hash_1 = codec::hex_decode("0xe79739ac82960be8bedb5175203bd65880b0c45c5c0286d54b5bc6eb4bac3898");
			superchain::coin_utxo input_p2wpkh_1;
			input_p2wpkh_1.link = superchain::wallet_link(seed, wallet.encoded_public_key, wallet.encoded_addresses[6]);
			input_p2wpkh_1.transaction_id = "5594c04289179bff0f434e5349fafbaa4d43da403b9dc7a637f5afe035b99729";
			input_p2wpkh_1.value = 0.1;

			auto input_p2tr_public_key = compositions::secp256k1_point_t(wallet.public_key);
			auto input_p2tr_tweak = compositions::secp256k1_scalar_t(codec::hex_decode("0x04c32a8b5fae170a7a0d28332a663b96f43d24ed4c9db30dfdd9d9d053d3d3e6"));
			auto input_p2tr_tweaked_public_key = compositions::secp256k1_schnorr_compositor::to_tweaked_public_key(input_p2tr_public_key, input_p2tr_tweak).expect("failed to tweak a public key");
			auto input_p2tr_hash = codec::hex_decode("0x50cc324f902032625ba70fdfee889032a7ff4de1c7732dc3982b72c1ba2df8b5");
			superchain::coin_utxo input_p2tr;
			input_p2tr.link = superchain::wallet_link(seed, wallet.encoded_public_key, wallet.encoded_addresses[4]);
			input_p2tr.transaction_id = "988fcb7035c0f51688ddcfaf92ec8fdd0e9bda8b53aa3403bf096611147fb325";
			input_p2tr.value = 0.1;

			auto input_p2wpkh_hash_2 = codec::hex_decode("0x16a41f749d25f7ebae96aabd62207c2189ac3623b2ddee4560213a3563f81042");
			superchain::coin_utxo input_p2wpkh_2;
			input_p2wpkh_2.link = superchain::wallet_link(seed, wallet.encoded_public_key, wallet.encoded_addresses[6]);
			input_p2wpkh_2.transaction_id = "9b7a67a6a46f48f896c1de89d479d9d1f5b284809065671ff931c800e1041530";
			input_p2wpkh_2.value = 0.1;

			auto input_p2wsh_hash = codec::hex_decode("0x40cfd352d152929ada057d28c0e18f781a8b9ddb24df1b6381b0738c8f0ccbb9");
			superchain::coin_utxo input_p2wsh;
			input_p2wsh.link = superchain::wallet_link(seed, wallet.encoded_public_key, wallet.encoded_addresses[5]);
			input_p2wsh.transaction_id = "ccc7949d20241f04362c42e20125c83096a617b906e1d8123d1b8b08740c6025";
			input_p2wsh.index = 1;
			input_p2wsh.value = decimal("0.1001");

			auto input_p2pk_hash = codec::hex_decode("0xe665fd68a288da956f73810db79647a59dbbd6dafb0891f97364a0dfff520b2e");
			superchain::coin_utxo input_p2pk;
			input_p2pk.link = superchain::wallet_link(seed, wallet.encoded_public_key, wallet.encoded_addresses[1]);
			input_p2pk.transaction_id = "f0b0d2386cd578677df2380361410008d260fc827282904e54bdcb9e1d8cf62f";
			input_p2pk.index = 0;
			input_p2pk.value = decimal("0.0999");

			superchain::coin_utxo output_p2wpkh;
			output_p2wpkh.link = superchain::wallet_link::from_address("bcrt1q9ls8q57rsktvxn6krgjktd6jyukfpenyvd2sa3");
			output_p2wpkh.value = 0.65;

			superchain::coin_utxo output_p2pkh;
			output_p2pkh.link = input_p2pkh.link;
			output_p2pkh.index = 1;
			output_p2pkh.value = decimal("0.0499");

			superchain::prepared_transaction prepared;
			prepared.requires_input(algorithm::composition::type::secp256k1, wallet.public_key, (uint8_t*)input_p2pkh_hash.data(), input_p2pkh_hash.size(), std::move(input_p2pkh));
			prepared.requires_input(algorithm::composition::type::secp256k1, wallet.public_key, (uint8_t*)input_p2sh_hash.data(), input_p2sh_hash.size(), std::move(input_p2sh));
			prepared.requires_input(algorithm::composition::type::secp256k1, wallet.public_key, (uint8_t*)input_p2wpkh_hash_1.data(), input_p2wpkh_hash_1.size(), std::move(input_p2wpkh_1));
			prepared.requires_input(algorithm::composition::type::secp256k1_schnorr, input_p2tr_tweaked_public_key, (uint8_t*)input_p2tr_hash.data(), input_p2tr_hash.size(), std::move(input_p2tr));
			prepared.requires_input(algorithm::composition::type::secp256k1, wallet.public_key, (uint8_t*)input_p2wpkh_hash_2.data(), input_p2wpkh_hash_2.size(), std::move(input_p2wpkh_2));
			prepared.requires_input(algorithm::composition::type::secp256k1, wallet.public_key, (uint8_t*)input_p2wsh_hash.data(), input_p2wsh_hash.size(), std::move(input_p2wsh));
			prepared.requires_input(algorithm::composition::type::secp256k1, wallet.public_key, (uint8_t*)input_p2pk_hash.data(), input_p2pk_hash.size(), std::move(input_p2pk));
			prepared.requires_output(std::move(output_p2wpkh));
			prepared.requires_output(std::move(output_p2pkh));
			validate_transaction(asset, wallet, prepared, "p2pk, p2pkh, p2sh, p2wpkh, p2wsh, p2tr", "010000000001074098b2156e619d1d3b97f59f01c20db9251bda1f8efba3091ffea1c9bf402938010000006a473044022046925b2907405d191a5f22b51b1ba11a16e9a3fe7a32e31461a469e22c2a8c94022047409abc5a4dd4072673498b8b0e3b4041a23830df4ad26f5b9a3a4265a0c726012102986445ccfd323143f392b66b8cfc056df90ebdc110573e3395ee670d5043f23affffffffa0020807878c29d5e524b7945bf5c282cf3efe20022f7d512138a7038e1f7c3d000000001716001418e254169de2c06bbe881f971b312084bf7d7e1cffffffff2997b935e0aff537a6c79d3b40da434daafbfa49534e430fff9b178942c094550000000000ffffffff25b37f14116609bf0334aa538bda9b0edd8fec92afcfdd8816f5c03570cb8f980000000000ffffffff301504e100c831f91f6765908084b2f5d1d979d489dec196f8486fa4a6677a9b0000000000ffffffff25600c74088b1b3d12d8e106b917a69630c82501e2422c36041f24209d94c7cc0100000000ffffffff2ff68c1d9ecbbd544e90827282fc60d2080041610338f27d6778d56c38d2b0f000000000494830450221008874b0ee3db472bd5e6615597c6c60607d03fe4af2b761f3241ff1ee5c470d2202202c589ec0ad3195eba4cd6992b6ee41f2300a4cb86d52587308cc88251e89a81001ffffffff0240d2df03000000001600142fe07053c38596c34f561a2565b752272c90e66430244c00000000001976a91418e254169de2c06bbe881f971b312084bf7d7e1c88ac0002473044022063d5c078bcd2ce4f97351f4eded070a6ed4d0243f0307ef0009e030648bd3551022013a510ee2e5e1d6516efd424ff8d3bf4860af7e65f930f878afc53017bd9ba6c012102986445ccfd323143f392b66b8cfc056df90ebdc110573e3395ee670d5043f23a0247304402207e71dff15ac4345c3dbb21607aea03ce07b1d9ceb443dcafa2839f72f28b705f022039fb2ab19dac81c76c12a3754a693c240321061efafae0e31197240b1f8ad4e6012102986445ccfd323143f392b66b8cfc056df90ebdc110573e3395ee670d5043f23a014026371d3a2baaf32f56cc0e8bb0f940d243facb694ee877b34540100c5498a2ef6698effdc811e516e62ba20f187ebdc25e30208b787eac053875292088c09a5602483045022100bbccdb0362de1e00aa9a9baf6e06a8a4fded4b6f5f65487ec2f058d72949d46602205a1555cc5d246c4a7669d1f7bb5fa7cad4ff47ed77aac4b6624319633c7736f9012102986445ccfd323143f392b66b8cfc056df90ebdc110573e3395ee670d5043f23a03483045022100c42af7a3a07f0f86139811ad20020f68885ab90531ac5c62070c7c613a35ae5302205bbf7b511e34e13eb29d15311ee77fc54508b5c66246c52e199bd450dfa93e07012102986445ccfd323143f392b66b8cfc056df90ebdc110573e3395ee670d5043f23a1976a91418e254169de2c06bbe881f971b312084bf7d7e1c88ac0000000000");
			if (unit != nullptr)
				unit->all_address_types = false;
		});
		tester::use_clean_state([&]()
		{
			auto asset = algorithm::asset::id_of("BCH");
			auto state = storages::superchainstate(asset);
			auto wallet = create_wallet(asset);

			auto input_p2pkh_hash = codec::hex_decode("0x06da9b13756115c79c0361a083d340c75ced09ddfec9a530601d73a0021ba6a5");
			superchain::coin_utxo input_p2pkh;
			input_p2pkh.link = superchain::wallet_link(seed, wallet.encoded_public_key, wallet.encoded_addresses[1]);
			input_p2pkh.transaction_id = "8d4157a810c52d392c871867fcb5e5375df7102857eea5d770781737c67e5ed4";
			input_p2pkh.index = 0;
			input_p2pkh.value = 0.1;

			superchain::coin_utxo output_p2pkh;
			output_p2pkh.link = superchain::wallet_link::from_address("bchreg:qzpz97kqvz9jj6tdr6wxdt7zyh7vtm8nwyy4ajnft4");
			output_p2pkh.index = 0;
			output_p2pkh.value = decimal("0.099");

			superchain::prepared_transaction prepared;
			prepared.requires_input(algorithm::composition::type::secp256k1, wallet.public_key, (uint8_t*)input_p2pkh_hash.data(), input_p2pkh_hash.size(), std::move(input_p2pkh));
			prepared.requires_output(std::move(output_p2pkh));
			validate_transaction(asset, wallet, prepared, "p2pkh", "0100000001d45e7ec637177870d7a5ee572810f75d37e5b5fc6718872c392dc510a857418d000000006b483045022100e543a68f96874a63bd60b5622d6c95a6e56285a9c65f5feadbd4106711c72ce302207e7125137db51622a64d6500a721e42194ef3687e41071850e3f42e83a24270e412102986445ccfd323143f392b66b8cfc056df90ebdc110573e3395ee670d5043f23affffffff01e00f9700000000001976a9148222fac0608b29696d1e9c66afc225fcc5ecf37188ac00000000");
		});
		tester::use_clean_state([&]()
		{
			auto asset = algorithm::asset::id_of("ETH");
			auto state = storages::superchainstate(asset);
			auto wallet = create_wallet(asset);

			auto signable_link = superchain::wallet_link(seed, wallet.encoded_public_key, wallet.encoded_addresses.begin()->second);
			auto signable_message = codec::hex_decode("0x57d10c32396f3368c294f5987ff147ee4ffe3beae206678395b9531a188754fb");
			superchain::prepared_transaction prepared;
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
			validate_transaction(asset, wallet, prepared, "eip155, transfer", "0xf86d02843b9aca008252089492f9727da59be92f945a72f6ed9b5de8783e09d3872386f26fc100008083016e3ba0828a9818c68accb87d3c2bcb10756065a987af5e01c08fdd8dd2575703fd683aa078016b7b632859e37dd70df8b9c71f63b979f083bc88ed767f3adcd3f414b572");

			auto token_asset = algorithm::asset::id_of("ETH", "TT", "0xDcbcBF00604Bad29E53C60ac1151866Fa0CC2920");
			signable_link = superchain::wallet_link(seed, wallet.encoded_public_key, wallet.encoded_addresses.begin()->second);
			signable_message = codec::hex_decode("0x430483f3812b96bfe179cd21fb18580c5ba0919c1e25090d9fd740bb238d7bdf");
			prepared = superchain::prepared_transaction();
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
			validate_transaction(asset, wallet, prepared, "eip155, erc20 transfer", "0xf8ab01843b9aca0082c64694dcbcbf00604bad29e53c60ac1151866fa0cc292080b844a9059cbb000000000000000000000000ba119f26a40145b463dfcae2590b68a057e81d3d00000000000000000000000000000000000000000000001b4486fafde57c000083016e3ca0ae47df7c4a500fe37bb59c7fdc814582c77395f4dffc99245a6588ea934a600ba04d48b4cd07c0c134723903545cce1444c7e48df052559716f65459ba73d6fca7");

			signable_link = superchain::wallet_link(seed, wallet.encoded_public_key, wallet.encoded_addresses.begin()->second);
			signable_message = codec::hex_decode("0xc91fa85db3a84bb26a64a81166f47113e8ea7eae1df6f8c19bd0504cb3fd39b9");
			prepared = superchain::prepared_transaction();
			prepared.requires_account_input(algorithm::composition::type::secp256k1, std::move(signable_link), wallet.public_key, (uint8_t*)signable_message.data(), signable_message.size(), { { asset, decimal("0.100021") } });
			prepared.requires_account_output("0x92F9727Da59BE92F945a72F6eD9b5De8783e09D3", { { asset, 0.1 } });
			prepared.requires_abi(format::variable(false));
			prepared.requires_abi(format::variable(string()));
			prepared.requires_abi(format::variable(decimal("1000000000000000000")));
			prepared.requires_abi(format::variable((uint32_t)2));
			prepared.requires_abi(format::variable((uint32_t)46860));
			prepared.requires_abi(format::variable((uint32_t)1000));
			prepared.requires_abi(format::variable((uint32_t)999999000));
			prepared.requires_abi(format::variable((uint32_t)21000));
			validate_transaction(asset, wallet, prepared, "eip1559, transfer", "0x02f87482b70c02843b9ac618843b9aca008252089492f9727da59be92f945a72f6ed9b5de8783e09d388016345785d8a000080c001a0665cbca34239422699d174834ceb55f230bc9388ea619b3222b6cd2d0b0dc44fa0358709583f20d4e2286f1225a7fbf490652f5ecf3a82b3f467fa83ceded24663");

			signable_link = superchain::wallet_link(seed, wallet.encoded_public_key, wallet.encoded_addresses.begin()->second);
			signable_message = codec::hex_decode("0x248fffefd534b260b4950554563b956dc7838defa9c33f53865a72473558f665");
			prepared = superchain::prepared_transaction();
			prepared.requires_account_input(algorithm::composition::type::secp256k1, std::move(signable_link), wallet.public_key, (uint8_t*)signable_message.data(), signable_message.size(), { { asset, decimal("0.000050758") }, { token_asset, decimal("503") } });
			prepared.requires_account_output("0xBA119F26A40145b463DFcae2590b68A057E81d3D", { { token_asset, decimal("503") } });
			prepared.requires_abi(format::variable(false));
			prepared.requires_abi(format::variable(string("0xDcbcBF00604Bad29E53C60ac1151866Fa0CC2920")));
			prepared.requires_abi(format::variable(decimal("1000000000000000000")));
			prepared.requires_abi(format::variable((uint32_t)2));
			prepared.requires_abi(format::variable((uint32_t)46860));
			prepared.requires_abi(format::variable((uint32_t)1000));
			prepared.requires_abi(format::variable((uint32_t)999999000));
			prepared.requires_abi(format::variable((uint32_t)50758));
			validate_transaction(asset, wallet, prepared, "eip1559, erc20 transfer", "0x02f8b182b70c02843b9ac618843b9aca0082c64694dcbcbf00604bad29e53c60ac1151866fa0cc292080b844a9059cbb000000000000000000000000ba119f26a40145b463dfcae2590b68a057e81d3d00000000000000000000000000000000000000000000001b4486fafde57c0000c080a000e18d4b9a489853e12d42f586cc9a2b48e7636590e66ef05d640a67c77ad05fa06765432ad540948931bc1ec530d6f3e06b3cd77eea670cd568d6b4be62fc2884");
		});
		tester::use_clean_state([&]()
		{
			auto asset = algorithm::asset::id_of("XRP");
			auto state = storages::superchainstate(asset);
			auto wallet = create_wallet(asset);

			auto signable_link = superchain::wallet_link(seed, wallet.encoded_public_key, wallet.encoded_addresses.begin()->second);
			auto signable_message = codec::hex_decode("0x53545800120000220000000024006115562e00000000201b006117fb614000000002b709b068400000000000000c7321ed2a994a958414a9dac047fd32001847954f89f464433cb04266fde37d6aff15448114c7f083a28227b588c13becf3f353e06d2e4f2fee8314f667b0ca50cc7709a220b0561b85e53a48461fa8");
			superchain::prepared_transaction prepared;
			prepared.requires_account_input(algorithm::composition::type::ed25519, std::move(signable_link), wallet.public_key, (uint8_t*)signable_message.data(), signable_message.size(), { { asset, decimal("45.550012") } });
			prepared.requires_account_output("rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe", { { asset, decimal("45.55") } });
			prepared.requires_abi(format::variable(string()));
			prepared.requires_abi(format::variable((uint32_t)6362454));
			prepared.requires_abi(format::variable((uint32_t)6363131));
			prepared.requires_abi(format::variable((uint32_t)12));
			validate_transaction(asset, wallet, prepared, "payment", "120000220000000024006115562E00000000201B006117FB614000000002B709B068400000000000000C7321ED2A994A958414A9DAC047FD32001847954F89F464433CB04266FDE37D6AFF15447440D358730D5280F136D566474B869A1A49F61C9F0C0B6DB51E77CB8E3CA8BD11964BCE5EA0DA4A4E927677455B6DF745F5C6DAA018B3E1CAE1AC98B31499F0B50B8114C7F083A28227B588C13BECF3F353E06D2E4F2FEE8314F667B0CA50CC7709A220B0561B85E53A48461FA8");
		});
		tester::use_clean_state([&]()
		{
			auto asset = algorithm::asset::id_of("XLM");
			auto state = storages::superchainstate(asset);
			auto wallet = create_wallet(asset);

			auto signable_link = superchain::wallet_link(seed, wallet.encoded_public_key, wallet.encoded_addresses.begin()->second);
			auto signable_message = codec::hex_decode("0x1a6e7daa8fbd8aab869ebeafc8650d911a948d6e8166aec4fcec5490e359f81d");
			superchain::prepared_transaction prepared;
			prepared.requires_account_input(algorithm::composition::type::ed25519, std::move(signable_link), wallet.public_key, (uint8_t*)signable_message.data(), signable_message.size(), { { asset, decimal("2200.00001") } });
			prepared.requires_account_output("GAIH3ULLFQ4DGSECF2AR555KZ4KNDGEKN4AFI4SU2M7B43MGK3QJZNSR", { { asset, decimal("2200") } });
			prepared.requires_abi(format::variable((uint64_t)1561327986278402));
			prepared.requires_abi(format::variable(false));
			prepared.requires_abi(format::variable(true));
			prepared.requires_abi(format::variable(string()));
			prepared.requires_abi(format::variable(string()));
			prepared.requires_abi(format::variable((uint8_t)0));
			validate_transaction(asset, wallet, prepared, "payment", "AAAAACqZSpWEFKnawEf9MgAYR5VPifRkQzywQmb9431q/xVEAAAAZAAFjAUAAAACAAAAAAAAAAAAAAABAAAAAAAAAAEAAAAAEH3Rayw4M0iCLoEe96rPFNGYim8AVHJU0z4ebYZW4JwAAAAAAAAABR9NXAAAAAAAAAAAAWr/FUQAAABAHsqVejb7HruH0aV6UzYwvWywdrywphFRCPxe//qGobXsVcgX3LzBl4uARxrUFwYqDSRHahYetDvO79gcvUIhBQ==");

			signable_link = superchain::wallet_link(seed, wallet.encoded_public_key, wallet.encoded_addresses.begin()->second);
			signable_message = codec::hex_decode("0xc23a0791a11ebefd653684792b4001e294440ce67979fb7a0dc2915ca4818e22");
			prepared = superchain::prepared_transaction();
			prepared.requires_account_input(algorithm::composition::type::ed25519, std::move(signable_link), wallet.public_key, (uint8_t*)signable_message.data(), signable_message.size(), { { asset, decimal("100.00001") } });
			prepared.requires_account_output("GD4QDZNYKL4VH7QGVP47DZZBEUB5KR53SI2RACPDNTHCOSAQJTN3RW2Z", { { asset, decimal("100") } });
			prepared.requires_abi(format::variable((uint64_t)1561327986278403));
			prepared.requires_abi(format::variable(true));
			prepared.requires_abi(format::variable(false));
			prepared.requires_abi(format::variable(string()));
			prepared.requires_abi(format::variable(string()));
			prepared.requires_abi(format::variable((uint8_t)0));
			validate_transaction(asset, wallet, prepared, "create_account", "AAAAACqZSpWEFKnawEf9MgAYR5VPifRkQzywQmb9431q/xVEAAAAZAAFjAUAAAADAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAA+QHluFL5U/4Gq/nx5yElA9VHu5I1EAnjbM4nSBBM27gAAAAAO5rKAAAAAAAAAAABav8VRAAAAEDwmgeOy3MUl/nyANi/pKs/m6EpmQa3fibonYTDwT3ZUt0Md36qD5xX9aNtqqaCyDyjNiTeXeyJKs8IPai0i+AG");
		});
		tester::use_clean_state([&]()
		{
			auto asset = algorithm::asset::id_of("SOL");
			auto state = storages::superchainstate(asset);
			auto wallet = create_wallet(asset);

			auto signable_link = superchain::wallet_link(seed, wallet.encoded_public_key, wallet.encoded_addresses.begin()->second);
			auto signable_message = codec::hex_decode("0x80010001032a994a958414a9dac047fd32001847954f89f464433cb04266fde37d6aff15440963cbfdea28293c02cd965c46e7a6f26bc5f26da4fa00dda8c8ade49f96dcad0000000000000000000000000000000000000000000000000000000000000000b83691e4405ab95ed6264b5942eb150deb64c9d0688940be0f6548da25de783c01020200010c02000000807a77230100000000");
			superchain::prepared_transaction prepared;
			prepared.requires_account_input(algorithm::composition::type::ed25519, std::move(signable_link), wallet.public_key, (uint8_t*)signable_message.data(), signable_message.size(), { { asset, decimal("4.890005") } });
			prepared.requires_account_output("devwuNsNYACyiEYxRNqMNseBpNnGfnd4ZwNHL7sphqv", { { asset, decimal("4.89") } });
			prepared.requires_abi(format::variable((uint64_t)1000000000));
			prepared.requires_abi(format::variable(string()));
			prepared.requires_abi(format::variable(string()));
			prepared.requires_abi(format::variable(string()));
			prepared.requires_abi(format::variable(string()));
			prepared.requires_abi(format::variable(string("DQ6H97iaf92qFZAWFSu57x74i47L4MJL5vjfun8pMrCj")));
			validate_transaction(asset, wallet, prepared, "transfer", "2mXpPxxdMg1J2wZ7EdNGpvMXrZ4THjKD8zAfgAtC2TN1VCUQWNg81QjJmr9hgTL8bu9DNNcc8LXM1U2ycp9J79tgUsyTu9hikqjHLbohWoLhvw7WztUvENarynygknqvGBB1jnYnQWhTvrYjbyBwhd4WQuVUhhiokKyfw6vq9ZJgbToU8anhgYGGgtBjpL3pzpAJVUoFF8A55LwLcsWUh7wcuvUfX22bBpKYbhBE3G4TwCv9Fi9xHsRrm4qfVm9eFQXCaoBVUdKtLuAJW5cRvUmBvp3zBZnzWfF8ebUb");

			auto token_asset = algorithm::asset::id_of("SOL", "9YaGkvrR1fjXSAm7LTcQYXZiZfub2EuWvVxBmRSHcwHZ", "9YaGkvrR1fjXSAm7LTcQYXZiZfub2EuWvVxBmRSHcwHZ");
			signable_link = superchain::wallet_link(seed, wallet.encoded_public_key, wallet.encoded_addresses.begin()->second);
			signable_message = codec::hex_decode("0x80010001052a994a958414a9dac047fd32001847954f89f464433cb04266fde37d6aff1544437b32d02edb961d6ffba969407c441a127befb1fe6885fa40f3d9e1dd7f9306d36dc35d5d43cb85d730bbf57899cb2266076f149fdf00b5491b69d1ad764df37ef41ef3474ed6a625c960cb38e5e9025a9edd6f63997d6c4c28f761dc23b67006ddf6e1d765a193d9cbe146ceeb79ac1cb485ed5f5b37913a8cf5857eff00a95abee248b8b08441f683b2e58d6b7c62bfa977bb775f0ef37facee593d0b1269010404010302000a0c50a50500000000000200");
			prepared = superchain::prepared_transaction();
			prepared.requires_account_input(algorithm::composition::type::ed25519, std::move(signable_link), wallet.public_key, (uint8_t*)signable_message.data(), signable_message.size(), { { asset, decimal("0.000015") }, { token_asset, decimal("3700") } });
			prepared.requires_account_output("4Bs1nFL71Yaq2HJ3pSk3WHdbhkWeqnrLYQZDhqjDfb53", { { token_asset, decimal("3700") } });
			prepared.requires_abi(format::variable((uint64_t)100));
			prepared.requires_abi(format::variable(string("9YaGkvrR1fjXSAm7LTcQYXZiZfub2EuWvVxBmRSHcwHZ")));
			prepared.requires_abi(format::variable(string("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")));
			prepared.requires_abi(format::variable(string("5YRGqmfQGcAii8szURA3ZztXfpre1ZnajJcS63GJi4yK")));
			prepared.requires_abi(format::variable(string("FEL6m5CE2P3JTW1ceo48VerTUSWDte6eXzgrcmcftvyQ")));
			prepared.requires_abi(format::variable(string("77EWfi8yvGJNRsC9BRHepMtBJ2RDEDAkZNWAT4YJNMYU")));
			validate_transaction(asset, wallet, prepared, "spl transfer", "7qSoGmgq68eUNs8tJZ8dDtyfpUHE64RaxrhFeARBKJdhtW4SsRitHzdkkH4uepUxZ599Y3RBhSyzSeb7mmFnrhER53hSbcyReBAPkeMfTWKeg7FnQuqxhAjnAf6zMyAiwWLHDWfDHoV1ovbUQXrdexZhHVRomMUwHX81rQv6RwCkfGnB7dfpysFQ2PeYztphz2Z2uSaY3x44X9AAZWpUk7MMHQxUvUNA6ESFoQTYYSNj8Vr5qdjV89AXYF2BfqVs1Qj3ZuHSaQbZFaEtfdanhzt7qJBBrZ4zV9QsbBCXDyPg6JncvZTePP7drV4Uf9SWKssN6AF5zaq5AVSE1GguJ5zfQoY6JbUuZ1zzX8PNbccQVtpvmfSqWn4EntLxP3D");

			signable_link = superchain::wallet_link(seed, wallet.encoded_public_key, wallet.encoded_addresses.begin()->second);
			signable_message = codec::hex_decode("0x80010002082a994a958414a9dac047fd32001847954f89f464433cb04266fde37d6aff1544437b32d02edb961d6ffba969407c441a127befb1fe6885fa40f3d9e1dd7f9306d36dc35d5d43cb85d730bbf57899cb2266076f149fdf00b5491b69d1ad764df37ef41ef3474ed6a625c960cb38e5e9025a9edd6f63997d6c4c28f761dc23b67006ddf6e1d765a193d9cbe146ceeb79ac1cb485ed5f5b37913a8cf5857eff00a92f5b6b548541c59c6580cdff889e30c53e19cb10241170ae041eaed436420aa200000000000000000000000000000000000000000000000000000000000000008c97258f4e2489f1bb3d1029148e0d830b5a1399daff1084048e7bd8dbe9f8595abee248b8b08441f683b2e58d6b7c62bfa977bb775f0ef37facee593d0b126902070600020503060401010404010302000a0c50a50500000000000200");
			prepared = superchain::prepared_transaction();
			prepared.requires_account_input(algorithm::composition::type::ed25519, std::move(signable_link), wallet.public_key, (uint8_t*)signable_message.data(), signable_message.size(), { { asset, decimal("0.000015") }, { token_asset, decimal("3700") } });
			prepared.requires_account_output("4Bs1nFL71Yaq2HJ3pSk3WHdbhkWeqnrLYQZDhqjDfb53", { { token_asset, decimal("3700") } });
			prepared.requires_abi(format::variable((uint64_t)100));
			prepared.requires_abi(format::variable(string("9YaGkvrR1fjXSAm7LTcQYXZiZfub2EuWvVxBmRSHcwHZ")));
			prepared.requires_abi(format::variable(string("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")));
			prepared.requires_abi(format::variable(string("5YRGqmfQGcAii8szURA3ZztXfpre1ZnajJcS63GJi4yK")));
			prepared.requires_abi(format::variable(string()));
			prepared.requires_abi(format::variable(string("77EWfi8yvGJNRsC9BRHepMtBJ2RDEDAkZNWAT4YJNMYU")));
			validate_transaction(asset, wallet, prepared, "spl create+transfer", "4ZaYUykgrB2uZiBGR9FzozSmoDp1xnao1QVaBNCEzDtL74e1wnnVNYYn5kJJsaVN3XnfjjkD5ivyHaDH3xTjA8FNyiALbsAf8ohPx2fHskdGh3PXWy6zQgA3W6QT25zg9LRtyyRjATL6AfyQ9uARw6P8sKPwY3c8cN3zuz3X8JqAjJyQZtNFJv4Sj1SWq2YFYVJYbbL5oNwEd7uKKC2FuG4TthH4A63NyuKSPwuVy1Xw4CBcfxDjn3PmVNjAawWF95dDdErtfwLPLbLxeu2BNjhuCHdedrZepJynoXfCxjKcB7mYPsWxCjUM36EY8kGnH4m2piuvumEhCLfX4bsDLkd4cVWs8f77TPNxwXpbPNnCNgd3i7yzAcyxPgArQ1gMVfE6vc3HaowmQsmf2hbywaQP29oZrMXCr7hPtV5mDBRhxkjqkt5jg6yc49F3QTDhQLnRLfGK1Gh3qgjPYnVwGtezBmdQZTabDw6BF1rDaNxfnXD2gQfEGPFWqJfESPvCeRCi59Yq2obWfKio");
		});
		tester::use_clean_state([&]()
		{
			auto asset = algorithm::asset::id_of("ADA");
			auto state = storages::superchainstate(asset);
			auto wallet = create_wallet(asset);

			auto input_hash = codec::hex_decode("0x14b33fbdd10c0931057b2c66e56b08cf01523480769153e3433050c571dc23e6");
			superchain::coin_utxo input;
			input.link = superchain::wallet_link(seed, wallet.encoded_public_key, wallet.encoded_addresses[1]);
			input.transaction_id = "f887787271fa3538f574bb0a95f1178377dd70a98813657764241fdf4e0ca7b7";
			input.index = 1;
			input.value = decimal("9965.667678");

			superchain::coin_utxo output_1;
			output_1.link = superchain::wallet_link::from_address("addr_test1vqeux7xwusdju9dvsj8h7mca9aup2k439kfmwy773xxc2hcu7zy99");
			output_1.index = 0;
			output_1.value = decimal("2100");

			superchain::coin_utxo output_2;
			output_2.link = input.link;
			output_2.index = 1;
			output_2.value = decimal("7865.501517");

			superchain::prepared_transaction prepared;
			prepared.requires_input(algorithm::composition::type::ed25519, wallet.public_key, (uint8_t*)input_hash.data(), input_hash.size(), std::move(input));
			prepared.requires_output(std::move(output_1));
			prepared.requires_output(std::move(output_2));
			prepared.requires_abi(format::variable((uint64_t)166161));
			validate_transaction(asset, wallet, prepared, "p2pkh", "84a30081825820f887787271fa3538f574bb0a95f1178377dd70a98813657764241fdf4e0ca7b7010182a200581d6033c378cee41b2e15ac848f7f6f1d2f78155ab12d93b713de898d855f011a7d2b7500a200581d6042a00dfc0e9577dd74673d4b90b1e4a00e8a7fe0778dd134d268a95f011b00000001d4d2074d021a00028911a100818258202a994a958414a9dac047fd32001847954f89f464433cb04266fde37d6aff15445840e28a2e306c97c2c3871d64c5830ac0ae2a8e575a699130075c55b67ab3029a5c83712d9e86b71dce110141bf4c8039f388c0e79eccb10c2b4f0a9e3abe08ce0df5f6");

			auto token_contract = "bd976e131cfc3956b806967b06530e48c20ed5498b46a5eb836b61c2";
			auto token_symbol = "tMILKv2";
			input_hash = codec::hex_decode("0x66bb498dd4f2840ef018b8392c58fd198f334474b5c9b96d7412b1b4cee39b0b");
			input = superchain::coin_utxo();
			input.link = superchain::wallet_link(seed, wallet.encoded_public_key, wallet.encoded_addresses[1]);
			input.transaction_id = "0f7cad6020aaf0c462cfb6cba2b5f4102910b7bf7101ed609eb887188b19ad6f";
			input.index = 1;
			input.value = decimal("9940.752346");
			input.apply_token_value(token_contract, token_symbol, decimal("999995689"), 0);

			output_1 = superchain::coin_utxo();
			output_1.link = superchain::wallet_link::from_address("addr_test1vzpkkthr9azvuagxcf0m27qvzdad7n95jutgcdtglgmhdns998vsz");
			output_1.index = 0;
			output_1.value = decimal("1.655136");
			output_1.apply_token_value(token_contract, token_symbol, decimal("65483"), 0);

			output_2 = superchain::coin_utxo();
			output_2.link = input.link;
			output_2.index = 1;
			output_2.value = decimal("9938.927089");
			output_2.apply_token_value(token_contract, token_symbol, decimal("999930206"), 0);

			prepared = superchain::prepared_transaction();
			prepared.requires_input(algorithm::composition::type::ed25519, wallet.public_key, (uint8_t*)input_hash.data(), input_hash.size(), std::move(input));
			prepared.requires_output(std::move(output_1));
			prepared.requires_output(std::move(output_2));
			prepared.requires_abi(format::variable((uint64_t)170121));
			validate_transaction(asset, wallet, prepared, "p2pkh asset", "84a300818258200f7cad6020aaf0c462cfb6cba2b5f4102910b7bf7101ed609eb887188b19ad6f010182a200581d60836b2ee32f44ce7506c25fb5780c137adf4cb497168c3568fa3776ce01821a00194160a1581cbd976e131cfc3956b806967b06530e48c20ed5498b46a5eb836b61c2a147744d494c4b763219ffcba200581d6042a00dfc0e9577dd74673d4b90b1e4a00e8a7fe0778dd134d268a95f01821b000000025067fdf1a1581cbd976e131cfc3956b806967b06530e48c20ed5498b46a5eb836b61c2a147744d494c4b76321a3b99b95e021a00029889a100818258202a994a958414a9dac047fd32001847954f89f464433cb04266fde37d6aff154458404a594cc96cd2aec42c68556ca1c90b06da654230fae3247e14e50d6896598352a6bbe24a45fc825bcae90161c2cad02faf343fdc8354e89ae676b27c8f646304f5f6");
		});
		tester::use_clean_state([&]()
		{
			auto asset = algorithm::asset::id_of("TRX");
			auto state = storages::superchainstate(asset);
			auto wallet = create_wallet(asset);

			auto signable_link = superchain::wallet_link(seed, wallet.encoded_public_key, wallet.encoded_addresses.begin()->second);
			auto signable_message = codec::hex_decode("0x6c30ab9d12ae48c5c6800533451ef201dcc807980ea18739301ac48c2ddef3ce");
			superchain::prepared_transaction prepared;
			prepared.requires_account_input(algorithm::composition::type::secp256k1, std::move(signable_link), wallet.public_key, (uint8_t*)signable_message.data(), signable_message.size(), { { asset, decimal("22.4") } });
			prepared.requires_account_output("TXNE2M4GSw6tjVsGeux9nbVEhihGU6hBeV", { { asset, 14 } });
			prepared.requires_abi(format::variable(string()));
			prepared.requires_abi(format::variable("091a"));
			prepared.requires_abi(format::variable("844ba957b61a108b"));
			prepared.requires_abi(format::variable((uint64_t)1744587342000));
			prepared.requires_abi(format::variable((uint64_t)1744587282000));
			prepared.requires_abi(format::variable((uint32_t)1000000));
			prepared.requires_abi(format::variable((uint64_t)150000000));
			validate_transaction(asset, wallet, prepared, "transfer", "78da8d53cb6edc300cfc179d83947a51d25edb4befbd058141515462d4bb5ed8de3c10e4df4b376d90b697da1779f89aa1472fe6615cc73a8939749a56b932dbd3d72fe660903d502dcd3a929039326680e87d8856ba03db9833a49241c8e6e48b074bac89ae35e99ec55c99851e87461b0df7f2a41d81c041b1e41ce41c42a51253454b16720d5021db5c328bf72e920ecb60adc300e45a0aa924c0e80413767d133246b48a95e415f58a35d71324873d05fdda1176128322162579448cc9851d97f486fa14acf32ad3c66059b570537abd1510d61e5c6cb1b6b590a44a8b0d2b6289d6edd942354257a8a21224d4399262ac1c6dcb85ab66db8239d89ca16a1e608206c439be292c00360379f6217dd89439bc189e4fdb42bc99c3cd8b39d34247d964d9230f345d643f6cf340ad2db2aebad6ff27a383e6c7932c7f14ffaf6e2da6e37c39292f1be0e7f3aa66793ecb7059266db51fafefe6f96e123a8feb35cfc74fe765de669ea7eb6f0b9dd62ecbe7dfe27ed56addbfa15b5d88f4a14e337f1feaf3263bd3dd39e663e09ed67bc5ff7692e6c8d3795c681be793724d2144f567704a58678e4759373a9edf232ebf45bac8308dc771d717e15de03ade9d68bb2ccaf4c650c9dd83f44c950b44269f7c2e125b77bd564f153345e1e8b9865c005b6e926ceb2512f8d620755777df124975a95070a1a7e6f55eb488817d76adc7aec6ed0c4eff654b54506f5fa8c2e84ab16c6e5f7f007e681395");

			auto token_asset = algorithm::asset::id_of("TRX", "GFC", "TUiyUe3uqtiT8cFkfhW6Q28Z99sY7o82Xr");
			signable_link = superchain::wallet_link(seed, wallet.encoded_public_key, wallet.encoded_addresses.begin()->second);
			signable_message = codec::hex_decode("0xf070bae36536973c5ca2956768882d2b9144ec74cff4673ffc418b8d2b0da9b0");
			prepared = superchain::prepared_transaction();
			prepared.requires_account_input(algorithm::composition::type::secp256k1, std::move(signable_link), wallet.public_key, (uint8_t*)signable_message.data(), signable_message.size(), { { asset, decimal("14.0228") }, { token_asset, decimal("8") } });
			prepared.requires_account_output("TXNE2M4GSw6tjVsGeux9nbVEhihGU6hBeV", { { token_asset, decimal("8") } });
			prepared.requires_abi(format::variable("TUiyUe3uqtiT8cFkfhW6Q28Z99sY7o82Xr"));
			prepared.requires_abi(format::variable("08ca"));
			prepared.requires_abi(format::variable("9dd563feb883a59e"));
			prepared.requires_abi(format::variable((uint64_t)1744587102000));
			prepared.requires_abi(format::variable((uint64_t)1744587042000));
			prepared.requires_abi(format::variable((uint64_t)1000000));
			prepared.requires_abi(format::variable((uint64_t)150000000));
			validate_transaction(asset, wallet, prepared, "trc20 transfer", "78dacd54c96edc300cfd179d83945a29ceb5bdf4dcde82604049d4c4a8271ed8ce8620ff5eba498ab46881a0a7ca8020bd47525cfd686e876528a3985de7719133b3de7ffe6476a6034261f129fa44e86bacec28264c3967d75c211b82540cb5f790d0f75e83cd252b038da980393333dfed1bafbcbf927bb5080c0eb29ad19d5a8bc97729397b8e24010ab074ce45bc779159c042b6dd3a263db1b71890105274a23e74fd30d51493554cdd53d42bd65c4740973a06bd6d4875128322a4f298223a0da7a996c310365e70636df218ac62c036065b91726d64b93702a96aab92256b5b0b28455a6ca9a444d1ba1fd2ad50488d9d75d243510cbd5e724b9c639790bb4f0ebc3817824613a996027f59c2254257f325013b4eeabb608ca546dbb22aeacb96520ef0cf0bd93adda141a39e9ef34d00366b92ab0ff8a66e66f768ea74bdce5c57b3bb7834279ef928abcc1b73cbe38d6c876751f3bf84a6014c77d732efb9b55996455d7b7f4555f935e25ff5df5963f3a403f47092fdcd3caae2763c3f4cd361143e0dcb799d8e1f4ef3b44e751acfbfcec3e120f39723cfebc7d734bfe8abee9fe94b2d8ff47d19a7fa6d5f1e56d9fcdba6cabc25ae78b952fcf7295319b93f0d33afc3746d763a532166b43a9600faee709465e5e3e92703e199e922fb71380eda0536be245b1d5d86c335af37b37a7b61c86a16098b97a08d8e813c61e68cb57b46f6a0ed911dc7e235d50aa456bdc79e2544892e13e9145364b2999395049e92d776a180b691fe862835e84ec833f70a243da323afc6bd76d366db5673f9f41d8cd25365");
		});
		tester::use_clean_state([&]()
		{
			auto asset = algorithm::asset::id_of("XMR");
			auto state = storages::superchainstate(asset);
			auto wallet = create_wallet(asset);

			superchain::coin_utxo input;
			input.link = superchain::wallet_link(seed, wallet.encoded_public_key, wallet.encoded_addresses.begin()->second);
			input.transaction_id = "102";
			input.index = 0;
			input.value = 0.01;
			input.extra = codec::hex_decode("0xd8705e0f3e2decea48fae350b23010a948e871cc95c54834004313c10b3b9b0d8c9b7e994d98d6c3593ab23f30a732b559294a2e353b49250dc1fabd41c6dd066600000000000000");

			superchain::coin_utxo output1;
			output1.link = superchain::wallet_link::from_address("887gyyu7y4LbLDY6QUcrgDGYMRJN1FKL8QUTwuL7HxosENMymJJEj7bZqBjiFU46ExMdjCNh3yUWHSVzHvKfMAvrLkYdyNF");
			output1.value = 0.005;
			output1.index = 0;

			superchain::coin_utxo output2;
			output2.link = superchain::wallet_link(algorithm::encoding::decode_0xhex256("0x9ef466bbda9be2a13d50c46bbd53c75a70607a4a3b5c67959b50234fa04f190c"), "1b25d81c9eb85ee5dd471f1e47d9c967ce6587bbca71462b4fd47c38bf11cbae:30ddcfeaca93e2e159e81145179b1eb9b9a140afd17ae70772308fe6f78f1f8a", "42en54HJ9KbfSyPoMWQCHvJN3vyruyqLR8FBPNXowEMYW8sSwgSiTboehBxTjFwg5jY4mSmhWEYKY2FEh4TQnLm4GdiJDwp");
			output2.value = decimal("0.0031436");
			output2.index = 1;

			superchain::prepared_transaction prepared;
			prepared.requires_shared_input(algorithm::composition::type::ed25519_clsag, wallet.public_key, std::move(input));
			prepared.requires_output(std::move(output1));
			prepared.requires_output(std::move(output2));
			prepared.requires_abi(format::variable(codec::hex_decode("0xf6b48b4d2827024154842aa515619e70ab80f994c0f6441f60d684f7f7295eb215d5404390090109204ac2c5fc1768ac64423f5d993c85e4d855d82bab37439ff0c35f157889e50fff8a0c95875bc009012a2a084a5ad95d60e80e94ef10eda34485957d89e2d10576578c704174bf0bc388635f0b4aff5c789d0c923a976af13744676be9be9f5c86ade43e1ebdcc6954f055e178924ad8705e0f3e2decea48fae350b23010a948e871cc95c54834004313c10b3b9b0d4a8c9b7e994d98d6c3593ab23f30a732b559294a2e353b49250dc1fabd41c6dd06096609104a88005845823323e59c04b968824a6f61a3e3a1376ac74a1e26e676c819c2221c4ae64e72cc71a686f2d917dc5142ca91d929579f3d541a275ad3562fb5cca65d90092c064ad8c2269ef81840b469346bbfae0cf087d3511b8e1fe04c96f455c63246b9bd5b4ab289be0e272fc64ccc3b811f1fdba3395a3701aceaf82dcdc4781ef85ff3a9960901064a22d56f16a2d52c7299c7c596ae5b46c2414b71eb5052b993606c9d6bbc4555104a50a3f64bab0f0136578d06613239b914f3746baba8855bd95b8a56f671b6dcee0901064ade5ef479f4a37f5eaa030085b3002568dea7ce6508d2231f2065217d810178e04af3b3c6e5b1b35d9a9f5f3960c21047597b9c1b97275e9a04ee978f349b926c8c0901064a240fa105f872148a3f8d050912c21887a9cba23bed329e1e162830e7c82ab64c4a5ddaa16b37503915e14f93dc8803fa97eb072221a0d1c8916ae143e69802ba540901064af7248e49ffdeb4114cbd66bf4152894172202a25aa5e730ef2870264873cb6de4aead60b7504850c7293e99f0f13823d0f0e99dd5f0dcce6f71a5f1990dd25e8ae0901064aaf97adee20cff9ade21fbadb7d8cde20ca0bb857d39f8e487850cab1e65b394c4a29b9cdf249ad0647966a57ba907ab7764a830cc2fb504bae0b6a2d0edc1278b70901064a30c2f7513b4e8f758893a9e596bf4f1732932cd45274fd88e6c4c7076169c5ce4ae3f54cb71ee97608d3b657b3046171dffc9dceb3dbe2756bc616d4aca2c27b190901064a34f87864785477cb61c3194e2c9efc24825292ef1eb4d7a870911d20ed725b8f4a67c8464266b9148b1a3cee91d3956279dea1cb800133fbfab9106e33ac0fef640901064a895cb8d3b4249ab81a34c3aa55bf4563e7a9a664852a574c7366de229ad3f5954ae97e47ad0ea542b03b440a83b5c297184b60efb0ae86f9df1912ee31494bc2180901064a2f55a12b45e17b9ed1ccf1ef284c0585698f98c3b1891c06b8879931537d4cd24a174aeb74d89d2ec4d2623c0fa3a95432da28e8349ef4569ed99dae6c3dc4033e0901064ae4b2f6b1de3ac321ea5f304194250cdfef117c670562722bf8d2cf12d7e78a2e4ab9e4dcb61022a867cef8d1c95416fd6f650bfa687c48007a7f3daf9c3a5271f10902064a0ae058453b59b109750ed7a2737d78e0b982954e430e91e4e9130b00f2e744dc4af88e75525d8173c1617a13f47f45821fb2e5504d8859c36443c6432b181d48230901064ae5498ca520a59274feb37c3eb4d30059e8a125357cde8293af31389d9e0b81054a429899f1eb62429298a89541015dfef5d71abc55ce6ffb1d78b6db27f5579eb30902064ae72852fa4b9a2d059db4b6dfcdbf328437f31bebe9863a3c11ed428ea7ac0a574a6bf94cf0b5fba40ad009245bf3c96566a0a0af066ba6a75e0dc9772121f7e3900901064af5e3349baef13b1f1f78cc7c289fb923083624c4dd578fdf5349b80f617152da4a0650c0f2f035e5adfa108e89cfa5bdaf12ec9f20363f21fbb61e34702980d6d7092a072a090209e04a3c6b2339986643f8f672dd0572e96ab222fa5c516c4d8a6ec78181b9ade8fbf732813b06999711cf894a6f1903a82a17584e3e00b3e8259b862f8f35cb1f154b3ecf525fe51681d92d024aa72305ffd093b31a6acf74220b6387317d9c8af7cbc173a3192c2c534d813e8f09374acf5e9b7588a4f29892504d610b76b486842bbbb8fda3d742895a6ba1a300d7d03208450850f3541e3b4aebbf5ab8bdf73ba1d2ecf05b5ffaf659539c3a5642413272216026ac078a31094ad6dff3e9c9cd7416e0b37cf96d83542f5c4a2f7424eff1e71943ee44f0436a2e6d012b948830acce33d11c7dcf007a8fc5df224d20d21e56955a0396b66d75ca9c490401f03f347195a60426a798852a83f5417c7ba55217af5f712beac7c10aafbb0f974ab06e6e157e8dbc9520fd47712d8ae1ca2f7f5af177373bd1fbbdfcf3aa64ac2a4a215451c3b11f0b2427c826f8ed1c26c7fba30dd59b60bbac3953bba48ae9db904acb55e9c0a6abab4901fec9acf97f667dc8f8ffb1f2dd88ae58115505bbc57ab54a4830feb384a9f3cbf806581be4c8ee03ec7d8bd48d6ab6dc13338976687834054a10df116c2193ecdd157c45bc0b16ebd7e680c8a5e2789c9b3df1e0f8705416064a1632759972af309f62e402dcade74c03cad093924528a0ab9366c5219d5f200809074a54aa2cf099a58e44155402d5adb6ac2c1a40eb04690bb3c5043b96e619ff7b1a4afafc024048c40bfe9ad8d0e4b9d3eaca5da9e9d8c44205748762425eb2d81b614a6e6f7573c4eba84282a5a7648646242243e21a002c40bd92c270707dc42c07d54a2b65ee2b0c8e1a56746b814dd15d54ba359e100a675969c1200de2c4f5d407594afdb6f89b9b5e9ef16f3a7b6ccce50ce50de37349cb191d03343385c67f1c4f584ac51543c6ff37df884a799ca87c0c3ecf4e24d92ce441220146f60f6fee265ce74a0697418195b983ae16392f6d6fa4fec54e4b2d6fb51a1b20eb7f19487314091909074ac9ff5c3cda9a19206184177785250ae368d821601248d98a8fa2281e1b6ee3d24a1e3079ab2d14e6984851d465d72c08f2f38d0417397860c32bfe9454d9b71d584a2e48384b1ae34da8ca2c23eaf4c845456d643c751b7b263bfbb82d17ad5d2cd04a8cbaffa7da8548841ff86d679e01dc08deadb6ae1581c28eeb495eca9a5793634ae433aed172ff8efb0b9f881e91eb8d491f2aeac2087685acaa245ca454ae5f544a23c488ecb21927ab1859218f3f1160d1d29e6ce192d3478ab535e60fafdf6b494a0323d2e7e27ff2495f642ababf73ae9b46838ea58ba14c8d3a3816948006056b4ae12d9ed05c2b5447f0928d333a2c433c35c0cf13fe7dea4d065b905be9b6400e0c806aa66e")));
			validate_transaction(asset, wallet, prepared, "pay to subaddress, pay to standard address", "0200010200102c01010101010101010101020102012ac2c5fc1768ac64423f5d993c85e4d855d82bab37439ff0c35f157889e50fff8a0200033c6b2339986643f8f672dd0572e96ab222fa5c516c4d8a6ec78181b9ade8fbf7e00003cf5e9b7588a4f29892504d610b76b486842bbbb8fda3d742895a6ba1a300d7d03743012b948830acce33d11c7dcf007a8fc5df224d20d21e56955a0396b66d75ca9c490401f03f347195a60426a798852a83f5417c7ba55217af5f712beac7c10aafbb0f970680d599f506813b06999711cf8908450850f3541e3ba72305ffd093b31a6acf74220b6387317d9c8af7cbc173a3192c2c534d813e8fd6dff3e9c9cd7416e0b37cf96d83542f5c4a2f7424eff1e71943ee44f0436a2e01b06e6e157e8dbc9520fd47712d8ae1ca2f7f5af177373bd1fbbdfcf3aa64ac2a215451c3b11f0b2427c826f8ed1c26c7fba30dd59b60bbac3953bba48ae9db90cb55e9c0a6abab4901fec9acf97f667dc8f8ffb1f2dd88ae58115505bbc57ab54830feb384a9f3cbf806581be4c8ee03ec7d8bd48d6ab6dc133389766878340510df116c2193ecdd157c45bc0b16ebd7e680c8a5e2789c9b3df1e0f8705416061632759972af309f62e402dcade74c03cad093924528a0ab9366c5219d5f20080754aa2cf099a58e44155402d5adb6ac2c1a40eb04690bb3c5043b96e619ff7b1afafc024048c40bfe9ad8d0e4b9d3eaca5da9e9d8c44205748762425eb2d81b616e6f7573c4eba84282a5a7648646242243e21a002c40bd92c270707dc42c07d52b65ee2b0c8e1a56746b814dd15d54ba359e100a675969c1200de2c4f5d40759fdb6f89b9b5e9ef16f3a7b6ccce50ce50de37349cb191d03343385c67f1c4f58c51543c6ff37df884a799ca87c0c3ecf4e24d92ce441220146f60f6fee265ce70697418195b983ae16392f6d6fa4fec54e4b2d6fb51a1b20eb7f19487314091907c9ff5c3cda9a19206184177785250ae368d821601248d98a8fa2281e1b6ee3d21e3079ab2d14e6984851d465d72c08f2f38d0417397860c32bfe9454d9b71d582e48384b1ae34da8ca2c23eaf4c845456d643c751b7b263bfbb82d17ad5d2cd08cbaffa7da8548841ff86d679e01dc08deadb6ae1581c28eeb495eca9a579363e433aed172ff8efb0b9f881e91eb8d491f2aeac2087685acaa245ca454ae5f5423c488ecb21927ab1859218f3f1160d1d29e6ce192d3478ab535e60fafdf6b490323d2e7e27ff2495f642ababf73ae9b46838ea58ba14c8d3a3816948006056bc2f58cc9e2ee608adb53afdf0c16acd8a49751a8419c13c812816b31c6c65f04b79a027ac00d5d7d44d52546fb6fb86b8d8d8f15df4f15c4018dc4cbf186bb06720343927b01b79b6b86c30baa711b31f366d362e3033eec10dc39bcb15e1104906f3d10e3def6d8dfbe1ffb73de16dfae2f360eb7f86cb674784db54e1f5306cb01f559b7c086bb5b1a9adb0681ab6fc4b4fc0ab3168295001045cbff1c710d27efa6e9f8866a7053cc1c3f06e3c38c96d5a2c5a0905680940b1b0fd5edfa059a2f26fa10c3f01a6c269cefcdf479255983219f2cfa7b929db4c12df86da000859c9cbe8c279c821918587625fb92863b0714c9df557248654b9353f6e88d0181b3ff9ee21ba9fc338e0118554df29519c0e2d4f57ea6f5917acef424b29f036e16284cdd86b4ccbf1e9a8d873de603c589365a0d646efd727e22dffd9bcc0abd6651ab789bed41281f8ea5f7d870c01d579b267bc1bf39e557f1a1ea574c08e53f3ac20ec43206fcb17b8e7a49b45c79b0bb2bc5f0a11c3ae323f8b4c48d004d1e91bdd96c0f0d1f444691f8ea8886ef2dc1f454851dee412807b2b0b1f30e7f925f852e0faaba4f82941065e7dacb073ffe0695a6e58c5c41ba51c6fc6207800ff83ed5754c1ce08d18a0a30860ff89ba1c27a95a1d58e6d1b2d3ebc5e80fce7fb9d4b5138c877d6eadbeeaa57dcc32084a1b2dda80a129454bc5bd6ae40e3a6150a5960f354119766105bde58ed16e10ec81925aeff8211cc1881d27c405c27336a094df0aecb8b6acd65c601b87c54f12c6c070b7c45e52a32ea868f63eff5c789d0c923a976af13744676be9be9f5c86ade43e1ebdcc6954f055e17892");
		});
	}
	/* blockchain containing all transaction types (zero balance accounts, valid regtest chain) */
	static void blockchain_full_coverage(vector<account_ref>* userdata)
	{
		tester::use_clean_state([&]()
		{
			vector<account_ref> users; vector<algorithm::pubkeyhash_t> contracts;
			for (size_t i = 0; i < kernel::params().policy.participation.min_per_account + 2; i++)
				users.push_back(account_ref(ledger::wallet::from_seed(stringify::text("00000%i", (int)i)), 0));

			format::tree results;
			format::tree* data = userdata ? nullptr : &results;
			TEST_BLOCK(&generators::setup_stage_1, "0x4ac925923511664a166d121086652707ef18e5e1ac22d289cb99e364dfc5194c", 1);
			TEST_BLOCK(std::bind(&generators::setup_custom, std::placeholders::_1, std::placeholders::_2, 2, 1, 0), "0xfa43969e1e426980619035b91584e5561489f9604cd65ebdee2f043a122861d4", 2);
			TEST_BLOCK(&generators::route_stage_1, "0x748fbe9bb5dae9141db46d250a89d1cc8da3b8cde90a20e1dae66e0eda22c231", 3);
			TEST_BLOCK(&generators::route_stage_2, "0x30897f8f16ff388b8effa893ed3c560382bd14d70014229996aee911dcc254df", 5);
			TEST_BLOCK(&generators::route_stage_3, "0x05f0cd8e28a314b7f457b31c00a99cf0ccf25b19c8659ac62f705c69682d5eff", 6);
			TEST_BLOCK(&generators::attestate_stage_1, "0x94f24444eba13f9fb36f685ce16714d9358880f6ef180c2dc924dbe05dd0630e", 8);
			TEST_BLOCK(&generators::transfer_stage_1, "0xb0cc03a4d0d98eed256affa4639f82a4f0bf8c0174ea5288fec4c94e97e87fc3", 9);
			TEST_BLOCK(&generators::transfer_stage_2, "0x7f1b8fa162d707fa36db07bed57fd249103b392ec8f1f2ca3fa1265263b882f0", 10);
			TEST_BLOCK(std::bind(&generators::transfer_custom, std::placeholders::_1, std::placeholders::_2, 0, algorithm::asset::id_of("BTC"), users[2].wallet.get_address(), 0.05), "0x07a11627f502a9205488b5290962a6f21deff5aadf3f2b616a82970a926a5c17", 11);
			TEST_BLOCK(std::bind(&generators::deploy_stage_1, std::placeholders::_1, std::placeholders::_2, &contracts), "0xce80009457417a091a7459976e26775101865b21017ebd92b477f683bd77a483", 12);
			TEST_BLOCK(std::bind(&generators::deploy_stage_2, std::placeholders::_1, std::placeholders::_2, &contracts), "0xfdd5617bbbcff8d8422c704244a7f0dbc72b1d585a2f494af6c1f7c21f5616b9", 13);
			TEST_BLOCK(std::bind(&generators::call_stage_1, std::placeholders::_1, std::placeholders::_2, &contracts), "0x7b0d23c836ce97c08af7d3540df05ff5f8d7ebda950f4bbb94f040fd8c00e30b", 14);
			TEST_BLOCK(&generators::rollup_stage_1, "0xd73bd5ce61765dd2ed5a2faa121b86f346eed6c9f7da09e1a40f2aaafb3a5ebb", 15);
			TEST_BLOCK(std::bind(&generators::setup_custom, std::placeholders::_1, std::placeholders::_2, 2, 0, 1), "0xfa8990b0ca1d8bda82d83b23891f6fd75d59049db6d0a3d101089da54bb38a3c", 16);
			TEST_BLOCK_FAULTY(&generators::migrate_stage_1, "0x1f93692f08eba07a3c992dbfa8f0fa0fe6b241f9bb53995d3f7d0a8bf0885148", 17);
			TEST_BLOCK(&generators::migrate_stage_2, "0x71fe701711c4edda17d21d2e3c2438d3407d040b8a37391d63e06451f1d46972", 19);
			TEST_BLOCK(&generators::migrate_stage_3, "0x95d21eaafc3f98a12d31c28b05c05d7519058c177fa35c3e424828baa85b6a27", 20);
			TEST_BLOCK(&generators::migrate_stage_4, "0x04e9af5fda33db1053961fbc7bfaaa603b92f715698f96db0e603c3f0118a5fe", 22);
			TEST_BLOCK(&generators::withdraw_stage_1, "0x23554a656f663c0753637856598a5fdb75de7d3cee5bd7859a9cee0ace6c0c4b", 24);
			TEST_BLOCK(&generators::withdraw_stage_2, "0x399aceddb3a5e2fd56fd016f9b41a5c56ea33e6d91c95e1dd39ab7ec94f7fba1", 26);
			TEST_BLOCK(&generators::withdraw_stage_3, "0xbcaee5e38348a76d6a9881b7b0a0752d55ed9c00fab2bb09a9004e3d3658535f", 28);
			TEST_BLOCK(&generators::withdraw_stage_4, "0x0bc07f749d78012114514767792498b052c91d4e9f1d4c49cdc8e7f218045765", 29);
			TEST_BLOCK(&generators::withdraw_stage_5, "0xe526f1dc9bd331dfe02b1424b3ee4c56266ab5577cc589e3f97a08c86671eb8f", 30);
			TEST_BLOCK(&generators::withdraw_stage_6, "0xa5d830e296ef79fce1b94d5e30452642ca746cde917d8485d0d204002422fa79", 31);
			TEST_BLOCK(&generators::withdraw_stage_7, "0x61b85f00f18569175c2f7f8bf592728a9c7287ca3d866c695c36b7307dd4fa41", 33);
			TEST_BLOCK(&generators::withdraw_stage_8, "0xebe193a121b5471c077c2a9d2a982fb38da63f930f9e08468606f19440cd7e6f", 35);
			TEST_BLOCK(std::bind(&generators::setup_custom, std::placeholders::_1, std::placeholders::_2, 2, 1, 0), "0x3e97b614ea627ffe540cab570a65fcf2067558e26f038e712563d5159048b202", 37);
			TEST_BLOCK_FALLBACK(&generators::production_stage_1, "0xb725bd931ecfdec18ab907e3a33dbee76907d1a94bb412f8d158f6078a098320", 38);
			TEST_BLOCK(&generators::production_stage_2, "0x3adf967ac76afdb7a0d669bf75b992ba58e8c3a49fca3c447f94c7c5645d427e", 39);
			if (userdata != nullptr)
				*userdata = std::move(users);
			else
				console::get()->write_line(data->as_json(true));
		});
	}
	/* blockchain containing setup transactions for p2p testing (zero balance accounts, valid regtest chain) */
	static void blockchain_bridge_coverage(vector<account_ref>* userdata)
	{
		tester::use_clean_state([&]()
		{
			vector<account_ref> users;
			for (size_t i = 0; i < kernel::params().policy.participation.min_per_account + 2; i++)
				users.push_back(account_ref(ledger::wallet::from_seed(stringify::text("00000%i", (int)i)), 0));

			format::tree results;
			format::tree* data = userdata ? nullptr : &results;
			TEST_BLOCK(&generators::setup_stage_2, "0xff1f0d9b5aa59fe404d831f7bfa8ab1b2158897524e35a72a7a6becda934cef2", 1);
			TEST_BLOCK(&generators::route_stage_4, "0x0f2165530d9dfd6de1d8bc0811c476b9b200fb836118e68913ce741d83fa52c6", 2);
			if (userdata != nullptr)
				*userdata = std::move(users);
			else
				console::get()->write_line(data->as_json(true));
		});
	}
	/* blockchain containing some transaction types (non-zero balance accounts, valid regtest chain) */
	static void blockchain_partial_coverage(vector<account_ref>* userdata)
	{
		tester::use_clean_state([&]()
		{
			vector<account_ref> users;
			for (size_t i = 0; i < kernel::params().policy.participation.min_per_account + 1; i++)
				users.push_back(account_ref(ledger::wallet::from_seed(stringify::text("00000%i", (int)i)), 0));

			format::tree results;
			format::tree* data = userdata ? nullptr : &results;
			TEST_BLOCK(&generators::setup_stage_0, "0x723017f46bb8f47c72020a104fe4fa66086dae7fd9f79ce048e73bd5be5c877c", 1);
			TEST_BLOCK(&generators::route_stage_0, "0xfdc09ff9e80bddb1876b496123b59168fd8091d897e674e804a4fc7ffcde2147", 2);
			TEST_BLOCK(&generators::attestate_stage_0, "0x4a7f75c0d1bcfbd80a0e71373f09f133044d869a076fd70c2179cd560ca20957", 4);
			TEST_BLOCK(std::bind(&generators::transfer_custom, std::placeholders::_1, std::placeholders::_2, 0, algorithm::asset::id_of("BTC"), "tcrt1x00g22stp0qcprrxra7x2pz2au33armtfc50460", 5), "0x77c591a7afc372b33513e45738266c322da93c7573e3f57e2f82e15feadbe2ab", 5);
			TEST_BLOCK(std::bind(&generators::transfer_custom, std::placeholders::_1, std::placeholders::_2, 0, algorithm::asset::id_of("ETH", "tBTC", "0x18084fbA666a33d37592fA2633fD49a74DD93a88"), "tcrt1x00g22stp0qcprrxra7x2pz2au33armtfc50460", 5), "0x818cf525e43551b7acb973d5b1f6f32c85c0a16ba61e6923b6c13f3208782238", 6);
			TEST_BLOCK(std::bind(&generators::transfer_custom, std::placeholders::_1, std::placeholders::_2, 0, algorithm::asset::id_of("ETH", "USDT", "0xdAC17F958D2ee523a2206206994597C13D831ec7"), "tcrt1x00g22stp0qcprrxra7x2pz2au33armtfc50460", 300000), "0x2e02257f06a285bb305ae6d459ce085c773ed2c9226dd0a8b7869bf547a4ab68", 7);
			TEST_BLOCK(std::bind(&generators::transfer_custom, std::placeholders::_1, std::placeholders::_2, 0, algorithm::asset::id_of("TRX", "USDT", "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"), "tcrt1x00g22stp0qcprrxra7x2pz2au33armtfc50460", 200000), "0x2aa0cbce86c40cfbdb7591c3033113d83e5e896e014525254181963edbc8d1d3", 8);
			TEST_BLOCK(std::bind(&generators::transfer_custom, std::placeholders::_1, std::placeholders::_2, 0, algorithm::asset::id_of("BTC"), "tcrt1xu0k7jd2hsv2x5h80tcslpk3n0kvzzw5kup6vng", 5), "0x647b0b2d5fee38d1fcef4a6a7454dfe269505846a6b6e6b9a9391ab3a358d2d6", 9);
			TEST_BLOCK(std::bind(&generators::transfer_custom, std::placeholders::_1, std::placeholders::_2, 0, algorithm::asset::id_of("ETH", "tBTC", "0x18084fbA666a33d37592fA2633fD49a74DD93a88"), "tcrt1xu0k7jd2hsv2x5h80tcslpk3n0kvzzw5kup6vng", 5), "0x716f4d7ca7df235a036011d086694aa574f46e5c6afc91af0549f46bdbe9f2f8", 10);
			TEST_BLOCK(std::bind(&generators::transfer_custom, std::placeholders::_1, std::placeholders::_2, 0, algorithm::asset::id_of("ETH", "USDT", "0xdAC17F958D2ee523a2206206994597C13D831ec7"), "tcrt1xu0k7jd2hsv2x5h80tcslpk3n0kvzzw5kup6vng", 300000), "0x05be0f78f4016673685f0a059a8ff6566e014a2c28f7456d96cceffa6f707fe3", 11);
			TEST_BLOCK(std::bind(&generators::transfer_custom, std::placeholders::_1, std::placeholders::_2, 0, algorithm::asset::id_of("TRX", "USDT", "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"), "tcrt1xu0k7jd2hsv2x5h80tcslpk3n0kvzzw5kup6vng", 200000), "0xcb2a06c867a37d8b0a5202458238ceb230a3d6c05a7ea6a0ec0cadcdfe8caf55", 12);
			if (userdata != nullptr)
				*userdata = std::move(users);
			else
				console::get()->write_line(data->as_json(true));
		});
	}
	/* blockchain exclusively for testing bridges of specific networks (possibly non-zero balance accounts, valid regtest chain) */
	static void blockchain_integration_coverage(const algorithm::asset_id& asset, const std::string_view& url, const std::string_view& deposit_account, const std::string_view& withdraw_account, const decimal& deposit_value, const decimal& bridge_fee, std::function<uint64_t()>&& new_block, std::function<void(const std::string_view&, const std::string_view&, const algorithm::asset_id&, const decimal&)>&& new_transaction)
	{
		tester::use_clean_state([&]()
		{
			vector<account_ref> producers;
			for (size_t i = 0; i < kernel::params().policy.participation.max_per_account; i++)
				producers.push_back(account_ref(ledger::wallet::from_seed(stringify::text("00000%i", (int)i)), 0));

			auto native_asset = algorithm::asset::base_id_of(asset);
			auto* term = console::get();
			auto& [user1, user1_nonce] = producers[0];
			auto& [user2, user2_nonce] = producers[1];
			auto& [user3, user3_nonce] = producers[2];
			auto* setup = memory::init<transactions::setup>();
			setup->asset = native_asset;
			setup->allocate_production_stake(decimal::zero());
			setup->allocate_attestation_stake(native_asset, decimal::zero(), 0);
			setup->allocate_bridge(native_asset, (uint8_t)kernel::params().policy.participation.min_per_account, bridge_fee);
			setup->allocate_participation_stake(decimal::zero());
			setup->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
			tester::new_block_from_one(nullptr, producers, setup, tester::block_type::normal);

			for (size_t i = 3; i < producers.size(); i++)
			{
				auto& [user, user_nonce] = producers[i];
				setup = memory::init<transactions::setup>();
				setup->asset = native_asset;
				setup->allocate_attestation_stake(native_asset, decimal::zero(), 0);
				setup->allocate_participation_stake(decimal::zero());
				setup->sign(user.secret_key, user_nonce++, decimal::zero()).expect("pre-validation failed");
				tester::new_block_from_one(nullptr, producers, setup, tester::block_type::normal);
			}

			auto executor = ledger::executor_context(nullptr);
			auto bridge_instance = executor.get_bridge_instances(native_asset, 0, 1)->front();
			auto* bridge_account = memory::init<transactions::route>();
			bridge_account->asset = native_asset;
			bridge_account->set_bridge_hash(bridge_instance.ref.hash);
			bridge_account->solve_pow_challenge(user1.public_key_hash, user1_nonce, 0);
			bridge_account->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
			tester::new_block_from_one(nullptr, producers, bridge_account, tester::block_type::normal);

			auto& config = kernel::mparams();
			config.user.superchain.listener = true;

			auto* offchain = superchain::bridge::get();
			auto params = (superchain::translation_unit::chainparams*)offchain->get_network_params(native_asset);
			kernel::mparams().user.superchain.polling_frequency = 3000;
			offchain->add_network_connection(native_asset, url, { }, 5.0);
			offchain->network_active = []() -> bool { return schedule::get()->is_active(); };
			offchain->network_fetch = [](const algorithm::asset_id&, const std::string_view& location, const std::string_view& method, const http::fetch_frame& options) -> expects_promise_system<http::response_frame>
			{
				return http::fetch(location, method, options);
			};

			auto receive_transaction = [&]()
			{
				bool awaiting_transaction = true;
				while (awaiting_transaction)
				{
					uint64_t block_number = new_block();
					term->fwrite_line("trying block %" PRIu64, block_number);
					offchain->scan_from_block_height(native_asset, (block_number > 0 ? block_number - 1 : 0) + params->sync_latency);
					auto result = coasync<expects_rt<vector<superchain::transaction_logs>>>([&]() -> expects_promise_rt<vector<superchain::transaction_logs>>
					{
						coreturn coawait(offchain->link_transactions(native_asset));
					}).get();
					if (!result)
					{
						term->fwrite_line("transaction(s) not found; retrying", block_number);
						continue;
					}

					for (auto& logs : *result)
					{
						auto transactions = vector<uptr<ledger::transaction_message>>();
						logs.report_logs(native_asset, offchain->get_network_instance(native_asset)->options, 0);
						for (auto& receipt : logs.receipts)
						{
							auto* transaction = memory::init<transactions::attestate>();
							transaction->asset = native_asset;
							transaction->set_computed_proof(receipt.as_proof_hash(native_asset), std::move(receipt), { });
							transactions.push_back(transaction);
						}

						if (!transactions.empty())
						{
							tester::new_block_from_list(nullptr, producers, std::move(transactions), tester::block_type::normal);
							awaiting_transaction = false;
						}
					}
				}
				term->write_line("transaction(s) found; continuing");
			};

			bridge_account = memory::init<transactions::route>();
			bridge_account->asset = native_asset;
			bridge_account->set_routing_address(deposit_account);
			bridge_account->set_bridge_hash(bridge_instance.ref.hash);
			bridge_account->solve_pow_challenge(user3.public_key_hash, user3_nonce, 0);
			bridge_account->sign(user3.secret_key, user3_nonce++, decimal::zero()).expect("pre-validation failed");
			tester::new_block_from_one(nullptr, producers, bridge_account, tester::block_type::normal);

			size_t deposits = 0;
			auto accounts = *executor.get_witness_accounts_by_purpose(params->routing == superchain::routing_policy::account ? user1.public_key_hash : user3.public_key_hash, states::witness_account::account_type::bridge, 0, 128);
			for (auto& account : accounts)
			{
				if (account.ref.hash == bridge_instance.ref.hash)
				{
					for (auto& [type, to_account] : account.addresses)
					{
						if (native_asset != asset)
						{
							new_transaction(deposit_account, to_account, native_asset, deposit_value);
							receive_transaction();
						}
						new_transaction(deposit_account, to_account, asset, deposit_value);
						receive_transaction();
						++deposits;
					}
				}
			}

			VI_PANIC(deposits > 0, "deposit address generation failed");
			auto expected_balance = deposit_value * deposits;
			auto native_balance = executor.get_account_balance(native_asset, user3.public_key_hash).expect("native balance mismatch").get_balance();
			VI_PANIC(native_asset == asset || native_balance >= expected_balance, "actual native balance is expected to be >=%s but is %s", expected_balance.to_string().c_str(), native_balance.to_string().c_str());

			auto balance = executor.get_account_balance(asset, user3.public_key_hash).expect("balance mismatch").get_balance();
			VI_PANIC(balance >= expected_balance, "actual balance is expected to be >=%s but is %s", expected_balance.to_string().c_str(), balance.to_string().c_str());

			auto withdrawal_value = native_asset == asset ? balance - bridge_fee : balance;
			term->write_line("outgoing transaction integration:");
			term->fwrite_line(" - withdraw %s into %.*s", withdrawal_value.to_string().c_str(), (int)withdraw_account.size(), withdraw_account.data());

			auto* withdraw = memory::init<transactions::withdraw>();
			withdraw->asset = asset;
			withdraw->set_routing_target(withdraw_account, withdrawal_value);
			withdraw->set_bridge_hash(bridge_instance.ref.hash);
			withdraw->sign(user3.secret_key, user3_nonce++, decimal::zero()).expect("pre-validation failed");
			tester::new_block_from_one(nullptr, producers, withdraw, tester::block_type::normal);

			auto chain = storages::chainstate();
			auto confirmation_block = chain.get_latest_block();
			VI_PANIC(confirmation_block && !confirmation_block->transactions.empty(), "blocks with withdrawal confirmation were not found");

			auto& confirmation = confirmation_block->transactions.front();
			VI_PANIC(confirmation.transaction->as_type() == transactions::broadcast::as_instance_type(), "no withdrawal confirmation");

			auto* confirmation_event = confirmation.receipt.find_event<transactions::broadcast>();
			auto* confirmation_transaction = (transactions::broadcast*)*confirmation.transaction;
			VI_PANIC(confirmation_transaction->proof && !confirmation_event, "withdrawal confirmation failed: %s", confirmation_event ? (confirmation_event->args.empty() ? "unknown error" : confirmation_event->args.front().as_blob().c_str()) : confirmation_transaction->proof.what().c_str());
			term->fwrite_line(" - block required for transaction %s", confirmation_transaction->proof->hashdata.c_str());
			receive_transaction();

			if (native_asset != asset)
			{
				auto target_balance = native_balance - bridge_fee;
				auto actual_balance = executor.get_account_balance(native_asset, user3.public_key_hash).or_else(states::account_balance(user3.public_key_hash, asset, nullptr)).get_balance();
				VI_PANIC(actual_balance >= target_balance, "actual balance is expected to be %s but is %s", target_balance.to_string().c_str(), actual_balance.to_string().c_str());
			}

			auto target_balance = native_asset == asset ? (balance - withdrawal_value - bridge_fee) : (balance - withdrawal_value);
			auto actual_balance = executor.get_account_balance(asset, user3.public_key_hash).or_else(states::account_balance(user3.public_key_hash, asset, nullptr)).get_balance();
			VI_PANIC(actual_balance >= target_balance, "actual balance is expected to be %s but is %s", target_balance.to_string().c_str(), actual_balance.to_string().c_str());
		});
	}
	/* verify current blockchain */
	static void blockchain_verification()
	{
		auto* term = console::get();
		auto chain = storages::chainstate();
		VI_PANIC(!chain.get_checkpoint_block_number().or_else(0), "blockchain cannot be validated without re-executing entire blockchain");
		
		uint64_t current_number = 1;
		format::tree data = format::tree::list();
		auto solver = ledger::solver_context();
		auto parent_block = chain.get_block_header_by_number(current_number > 0 ? current_number - 1 : 0);
		while (true)
		{
			auto next = chain.get_block_by_number(current_number++);
			if (!next)
				break;

			auto* result = data.push(format::tree::map());
			result->set("block_number", algorithm::encoding::serialize_uint256(next->number));
			result->set("block_hash", format::variable(algorithm::encoding::encode_0xhex256(next->as_hash())));

			ledger::block_evaluation evaluation;
			auto validation = ledger::solver_context::validate_solved_block(solver, parent_block.address(), *next, &evaluation);
			if (!validation)
			{
				result->set("status", format::variable("block validation test failed"));
				result->set("detail", format::variable(validation.error().message()));
				term->write_line(data.as_json(true));
				VI_PANIC(false, "block verification failed");
			}

			auto proof = next->as_proof(parent_block.address(), &evaluation.state);
			if (next->transaction_root != proof.transaction_tree.root())
			{
				term->write_line(data.as_json(true));
				VI_PANIC(false, "block verification failed - transaction merkle root deviation");
			}

			if (next->receipt_root != proof.receipt_tree.root())
			{
				term->write_line(data.as_json(true));
				VI_PANIC(false, "block verification failed - receipt merkle root deviation");
			}

			if (next->state_root != proof.state_tree.root())
			{
				term->write_line(data.as_json(true));
				VI_PANIC(false, "block verification failed - state merkle root deviation");
			}

			for (auto& tx : next->transactions)
			{
				if (!proof.has_transaction(tx.receipt.transaction_hash))
				{
					result->set("transaction_hash", format::variable(algorithm::encoding::encode_0xhex256(tx.receipt.transaction_hash)));
					result->set("status", format::variable("transaction merkle test failed"));
					term->write_line(data.as_json(true));
					VI_PANIC(false, "block verification failed");
				}
				else if (!proof.has_receipt(tx.receipt.as_hash()))
				{
					result->set("transaction_hash", format::variable(algorithm::encoding::encode_0xhex256(tx.receipt.transaction_hash)));
					result->set("status", format::variable("receipt merkle test failed"));
					term->write_line(data.as_json(true));
					VI_PANIC(false, "block verification failed");
				}
			}

			size_t state_index = 0;
			for (auto& [index, change] : evaluation.state)
			{
				uint256_t hash = change.state->as_hash();
				if (!proof.has_state(hash))
				{
					result->set("state_hash", format::variable(algorithm::encoding::encode_0xhex256(hash)));
					result->set("status", format::variable("state merkle test failed"));
					term->write_line(data.as_json(true));
					VI_PANIC(false, "block verification failed");
				}
			}

			result->set("status", format::variable("passed"));
			parent_block = *next;
			if (data.childs().size() > 32)
			{
				term->write_line(data.as_json(true));
				data.childs().clear();
			}
		}
		term->write_line(data.as_json(true));
	}
	/* gas estimation */
	static void blockchain_gas_estimation()
	{
		auto* term = console::get();
		term->capture_time();

		algorithm::seckey_t from;
		crypto::fill_random_bytes(from.blob, sizeof(from));

		algorithm::pubkeyhash_t to;
		crypto::fill_random_bytes(to.blob, sizeof(to));

		auto transaction = transactions::setup();
		transaction.allocate_production_stake(decimal::zero());
		transaction.allocate_attestation_stake(algorithm::asset::id_of("ETH"), decimal::zero(), 0.0001);
		transaction.allocate_attestation_stake(algorithm::asset::id_of("XRP"), decimal::zero(), 1.0);
		transaction.allocate_attestation_stake(algorithm::asset::id_of("BTC"), decimal::zero(), 0.00005);
		transaction.allocate_participation_stake(decimal::zero());
		VI_PANIC(transaction.sign(from, 1, decimal::zero()), "setup not signed");

		format::tree data = format::tree::map();
		data.set("setup_transaction_gas_limit", algorithm::encoding::serialize_uint256(transaction.gas_limit));
		data.set("block_gas_limit", algorithm::encoding::serialize_uint256(ledger::block_body::get_gas_limit()));
		data.set("slot_gas_limit", algorithm::encoding::serialize_uint256(ledger::block_body::get_slot_gas_limit()));
		term->write_line(data.as_json(true));
	}
};

int main(int argc, char* argv[])
{
	vitex::runtime scope;
	inline_args args = os::process::parse_args(argc, argv, (size_t)args_format::key | (size_t)args_format::key_value);
	kernel params = kernel(args);
	auto* term = console::get();
	term->show();

	int bad_entrypoint_exit_code = 0x39ce8025;
	int exit_code = bad_entrypoint_exit_code;
	auto test = args.get("test");
	if (test == "consensus")
	{
		/* consensus, discovery, superchain, rpc nodes */
		if (args.has("test-account-set"))
		{
			format::tree accounts = format::tree::list();
			for (size_t i = 0; i < 32; i++)
			{
				ledger::wallet wallet = ledger::wallet::from_seed(stringify::text("00000%i", (int)i));
				ledger::node node;
				node.address = socket_address(params.user.consensus.address, params.user.consensus.port);
				storages::mempoolstate().apply_node(std::make_pair(node, wallet), i == 0 ? storages::node_peer::runner : storages::node_peer::neighbor);
				accounts.push(wallet.as_secret_tree());
			}
			console::get()->write_line(accounts.as_json(true));
		}
		else
		{
			auto test_account = from_string<uint32_t>(args.get("test-account"));
			if (test_account)
			{
				ledger::wallet wallet = ledger::wallet::from_seed(stringify::text("00000%i", *test_account - 1));
				ledger::node node;
				node.address = socket_address(params.user.consensus.address, params.user.consensus.port);
				storages::mempoolstate().apply_node(std::make_pair(node, wallet), storages::node_peer::runner);
				console::get()->write_line(wallet.as_secret_tree().as_json(true));
			}
		}

		consensus::server_node consensus_service;
		discovery::server_node discovery_service;
		rpc::server_node rpc_service = rpc::server_node(&consensus_service);

		service_control control;
		control.bind(discovery_service.get_entrypoint());
		control.bind(consensus_service.get_entrypoint());
		control.bind(rpc_service.get_entrypoint());
		exit_code = control.launch();
	}
	else if (test == "benchmark")
	{
		/* blockchain derived from partial coverage test with 1920 additional blocks filled with configurable entropy transactions (non-zero balance accounts, valid regtest chain, entropy 0 - low entropy, entropy 1 - medium entropy, entropy 2 - high entropy) */
		auto* queue = schedule::get();
		queue->start(schedule::desc());

		vector<account_ref> users;
		tests::blockchain_partial_coverage(&users);
		const size_t block_count = 2048;
		const decimal starting_account_balance = decimal(500).truncate(12);
		auto transactions_mutex = std::mutex();
		auto transactions_queue = single_queue<vector<uptr<ledger::transaction_message>>>();
		auto checkpoint = [&](vector<uptr<ledger::transaction_message>>&& transactions, vector<account_ref>& users)
		{
			static uint64_t cumulative_transaction_count = 0, cumulative_transition_count = 0;
			auto cumulative_query_count = (uint64_t)ledger::storage_util::get_thread_invocations(); term->capture_time();
			auto block = tester::new_block_from_list(nullptr, users, std::move(transactions), tester::block_type::normal);
			auto time = term->get_captured_time();
			auto hash = algorithm::encoding::encode_0xhex256(block.as_hash());
			cumulative_transaction_count += block.transaction_count;
			cumulative_transition_count += block.transition_count;
			term->fwrite_line("%05" PRIu64 ": %.8s...%.8s = (d: %s / %.2f ms, t: %" PRIu64 " / %.2f hz, s: %" PRIu64 " / %.2f hz, q: %" PRIu64 " / %.2f hz)",
				block.number, hash.c_str(), hash.c_str() + (hash.size() - 8),
				algorithm::wesolowski::kdifficulty(block.difficulty).to_string().c_str(), time,
				cumulative_transaction_count, 1000.0 * (double)block.transaction_count / time,
				cumulative_transition_count, 1000.0 * (double)block.transition_count / time,
				cumulative_query_count, 1000.0 * (double)((uint64_t)ledger::storage_util::get_thread_invocations() - cumulative_query_count) / time);
		};
		auto make_checkpointer = [&]
		{
			return std::thread([&]()
			{
				auto transactions_subqueue = single_queue<vector<uptr<ledger::transaction_message>>>();
				for (size_t i = 0; i < block_count; i++)
				{
					if (transactions_subqueue.empty())
					{
						while (transactions_queue.empty())
							std::this_thread::sleep_for(std::chrono::milliseconds(1));

						umutex<std::mutex> unique(transactions_mutex);
						transactions_subqueue.swap(transactions_queue);
					}
					checkpoint(std::move(transactions_subqueue.front()), users);
					transactions_subqueue.pop();
				}
			});
		};
		auto feed_checkpointer = [&](vector<uptr<ledger::transaction_message>>&& transactions)
		{
			umutex<std::mutex> unique(transactions_mutex);
			transactions_queue.push(std::move(transactions));
			while (transactions_queue.size() >= 16)
			{
				unique.unlock();
				std::this_thread::sleep_for(std::chrono::milliseconds(1));
				unique.lock();
			}
		};
		auto& [user1, user1_nonce] = users[0];
		auto chain = storages::chainstate();
		auto mempool = storages::mempoolstate();
		auto executor = ledger::executor_context(nullptr);
		auto user1_addresses = *executor.get_witness_accounts_by_purpose(user1.public_key_hash, states::witness_account::account_type::bridge, 0, 128);
		auto user1_bridge_address = std::find_if(user1_addresses.begin(), user1_addresses.end(), [](states::witness_account& item) { return item.ref.asset == algorithm::asset::id_of("BTC"); });
		VI_PANIC(user1_bridge_address != user1_addresses.end(), "user 1 bridge address not found");
		auto entropy = from_string<uint8_t>(args.get("test-entropy")).expect("must provide a \"test-entropy\" flag (number in [1, 2, 3])");
		if (entropy == 1)
		{
			const size_t transaction_count = 384;
			const decimal outgoing_account_balance = starting_account_balance / decimal(block_count * (transaction_count + 64));
			const decimal incoming_quantity = starting_account_balance;
			auto* attestation = memory::init<transactions::attestate>();
			attestation->set_asset("BTC");
			attestation->set_finalized_proof(883669,
				"222fc360affb804ad2c34bba2269b36a64a86f017d05a9a60b237e8587bfc52b",
				{ superchain::value_transfer(attestation->asset, "mmtubFoJvXrBuBUQFf1RrowXUbsiPDYnYS", decimal(incoming_quantity)) },
				{ superchain::value_transfer(attestation->asset, user1_bridge_address->addresses.begin()->second, decimal(incoming_quantity)) });
			VI_PANIC(attestation->add_commitment(user1.secret_key), "attestation failed");
			attestation->sign(user1.secret_key, 0, decimal::zero()).expect("pre-validation failed");

			auto genesis = vector<uptr<ledger::transaction_message>>();
			genesis.push_back(attestation);
			checkpoint(std::move(genesis), users);

			auto receiver = ledger::wallet::from_seed("000002");
			auto checkpointer = make_checkpointer();
			for (size_t i = 0; i < block_count; i++)
			{
				vector<uptr<ledger::transaction_message>> transactions;
				transactions.resize(transaction_count);
				parallel::wail_all(parallel::for_each(transactions.begin(), transactions.end(), ELEMENTS_FEW, [&](uptr<ledger::transaction_message>& item)
				{
					double balance = (double)(std::max<uint64_t>(1000, crypto::random() % 10000)) / 10000.0;

					auto* transaction = memory::init<transactions::transfer>();
					transaction->set_asset("BTC");
					transaction->set_gas(decimal::zero(), 15000);
					transaction->set_to(receiver.public_key_hash, decimal(outgoing_account_balance).truncate(12) * decimal(balance));
					VI_PANIC(transaction->sign(user1.secret_key, user1_nonce++), "authentication failed");
					item = transaction;
				}));
				VI_SORT(transactions.begin(), transactions.end(), [](const uptr<ledger::transaction_message>& a, const uptr<ledger::transaction_message>& b) { return a->nonce < b->nonce; });
				feed_checkpointer(std::move(transactions));
			}
			if (checkpointer.joinable())
				checkpointer.join();
		}
		else if (entropy == 2)
		{
			const size_t transaction_count = 768;
			const size_t sender_count = 16;
			const size_t receiver_count = 32;
			const decimal outgoing_account_balance = starting_account_balance / decimal(block_count * (transaction_count + 64));
			const decimal incoming_quantity = starting_account_balance * sender_count;
			auto* attestation = memory::init<transactions::attestate>();
			attestation->set_asset("BTC");
			attestation->set_finalized_proof(883669,
				"222fc360affb804ad2c34bba2269b36a64a86f017d05a9a60b237e8587bfc52b",
				{ superchain::value_transfer(attestation->asset, "mmtubFoJvXrBuBUQFf1RrowXUbsiPDYnYS", decimal(incoming_quantity)) },
				{ superchain::value_transfer(attestation->asset, user1_bridge_address->addresses.begin()->second, decimal(incoming_quantity)) });
			VI_PANIC(attestation->add_commitment(user1.secret_key), "attestation failed");
			attestation->sign(user1.secret_key, 0, decimal::zero()).expect("pre-validation failed");

			auto genesis = vector<uptr<ledger::transaction_message>>();
			genesis.push_back(attestation);
			checkpoint(std::move(genesis), users);

			vector<account_ref> senders;
			senders.reserve(sender_count);
			for (size_t i = 0; i < sender_count; i++)
				senders.emplace_back(account_ref(ledger::wallet::from_seed(stringify::text("00001%i", (int)i)), 0));

			vector<account_ref> receivers;
			receivers.reserve(receiver_count);
			for (size_t i = 0; i < receiver_count; i++)
				receivers.emplace_back(account_ref(ledger::wallet::from_seed(stringify::text("00002%i", (int)i)), 0));

			auto* transfer = memory::init<transactions::transfer>();
			transfer->set_asset("BTC");
			for (auto& sender : senders)
				transfer->set_to(sender.wallet.public_key_hash, starting_account_balance);
			transfer->set_gas(decimal::zero(), ledger::block_body::get_gas_limit());
			VI_PANIC(transfer->sign(user1.secret_key, user1_nonce++), "authentication failed");

			genesis = vector<uptr<ledger::transaction_message>>();
			genesis.push_back(transfer);
			checkpoint(std::move(genesis), users);

			auto checkpointer = make_checkpointer();
			for (size_t i = 0; i < block_count; i++)
			{
				vector<uptr<ledger::transaction_message>> transactions;
				transactions.resize(transaction_count);
				parallel::wail_all(parallel::for_each(transactions.begin(), transactions.end(), ELEMENTS_FEW, [&](uptr<ledger::transaction_message>& item)
				{
					double balance = (double)(std::max<uint64_t>(1000, crypto::random() % 10000)) / 10000.0;
					auto& sender = senders[crypto::random() % senders.size()];
					auto& receiver = receivers[crypto::random() % receivers.size()];

					auto* transaction = memory::init<transactions::transfer>();
					transaction->set_asset("BTC");
					transaction->set_gas(decimal::zero(), 15000);
					transaction->set_to(receiver.wallet.public_key_hash, decimal(outgoing_account_balance).truncate(12) * decimal(balance));
					VI_PANIC(transaction->sign(sender.wallet.secret_key, sender.nonce++), "authentication failed");
					item = transaction;
				}));
				VI_SORT(transactions.begin(), transactions.end(), [](const uptr<ledger::transaction_message>& a, const uptr<ledger::transaction_message>& b) { return a->nonce < b->nonce; });
				feed_checkpointer(std::move(transactions));
			}
			if (checkpointer.joinable())
				checkpointer.join();
		}
		else if (entropy == 3)
		{
			const size_t transaction_count = 2660;
			const size_t sender_count = transaction_count;
			const decimal outgoing_account_balance = starting_account_balance / decimal(block_count * (transaction_count + 64));
			const decimal incoming_quantity = starting_account_balance * sender_count * 2;
			auto* attestation = memory::init<transactions::attestate>();
			attestation->set_asset("BTC");
			attestation->set_finalized_proof(883669,
				"222fc360affb804ad2c34bba2269b36a64a86f017d05a9a60b237e8587bfc52b",
				{ superchain::value_transfer(attestation->asset, "mmtubFoJvXrBuBUQFf1RrowXUbsiPDYnYS", decimal(incoming_quantity)) },
				{ superchain::value_transfer(attestation->asset, user1_bridge_address->addresses.begin()->second, decimal(incoming_quantity)) });
			VI_PANIC(attestation->add_commitment(user1.secret_key), "attestation failed");
			attestation->sign(user1.secret_key, 0, decimal::zero()).expect("pre-validation failed");

			auto genesis = vector<uptr<ledger::transaction_message>>();
			genesis.push_back(attestation);
			checkpoint(std::move(genesis), users);

			vector<account_ref> senders;
			senders.reserve(sender_count);
			for (size_t i = 0; i < sender_count; i++)
				senders.emplace_back(account_ref({ ledger::wallet::from_seed(stringify::text("00001%i", (int)i)), 0 }));

			auto* transfer = memory::init<transactions::transfer>();
			transfer->set_asset("BTC");
			for (auto& sender : senders)
				transfer->set_to(sender.wallet.public_key_hash, starting_account_balance);
			transfer->set_gas(decimal::zero(), ledger::block_body::get_gas_limit());
			VI_PANIC(transfer->sign(user1.secret_key, user1_nonce++), "authentication failed");

			genesis = vector<uptr<ledger::transaction_message>>();
			genesis.push_back(transfer);
			checkpoint(std::move(genesis), users);

			auto checkpointer = make_checkpointer();
			for (size_t i = 0; i < block_count; i++)
			{
				vector<uptr<ledger::transaction_message>> transactions;
				transactions.resize(transaction_count);
				parallel::wail_all(parallel::for_each(transactions.begin(), transactions.end(), ELEMENTS_FEW, [&](uptr<ledger::transaction_message>& item)
				{
					double balance = (double)(std::max<uint64_t>(1000, crypto::random() % 10000)) / 10000.0;
					auto& sender = senders[crypto::random() % senders.size()];

					uint8_t receiver[20];
					crypto::fill_random_bytes(receiver, sizeof(receiver));

					auto* transaction = memory::init<transactions::transfer>();
					transaction->set_asset("BTC");
					transaction->set_gas(decimal::zero(), 15000);
					transaction->set_to(receiver, decimal(outgoing_account_balance).truncate(12) * decimal(balance));
					VI_PANIC(transaction->sign(sender.wallet.secret_key, sender.nonce++), "authentication failed");
					item = transaction;
				}));
				VI_SORT(transactions.begin(), transactions.end(), [](const uptr<ledger::transaction_message>& a, const uptr<ledger::transaction_message>& b) { return a->nonce < b->nonce; });
				feed_checkpointer(std::move(transactions));
			}
			if (checkpointer.joinable())
				checkpointer.join();
		}

		auto tip_block = chain.get_latest_block();
		if (tip_block)
		{
			auto block_message = tip_block->as_message();
			term->fwrite_line("benchmark block size: ~%" PRIu64 " bytes", (uint64_t)(block_message.data.size() + 32));
		}

		queue->stop();
		exit_code = 0;
	}
	else if (test == "regression")
	{
		/* test case runner for regression testing */
		auto* queue = schedule::get();
		queue->start(schedule::desc());

		size_t executions = 0;
		vector<std::pair<std::string_view, std::function<void()>>> cases =
		{
			{ "generic / integer serialization", &tests::generic_integer_serialization },
			{ "generic / integer conversion", &tests::generic_integer_conversion },
			{ "generic / message serialization", &tests::generic_message_serialization },
			{ "cryptography / pow 256bit", &tests::cryptography_pow256 },
			{ "cryptography / wesolowski 2048bit", &tests::cryptography_wesolowski },
			{ "cryptography / signatures", &tests::cryptography_signatures },
			{ "cryptography / wallet", &tests::cryptography_wallet },
			{ "cryptography / wallet encryption", &tests::cryptography_wallet_encryption },
			{ "cryptography / transaction", &tests::cryptography_transaction },
			{ "cryptography / merkle tree", &tests::cryptography_merkle_tree },
			{ "cryptography / multichain wallet", &tests::cryptography_multichain_wallet },
			{ "cryptography / multichain mpc", &tests::cryptography_multichain_mpc },
			{ "cryptography / multichain transaction", &tests::cryptography_multichain_transaction },
			{ "blockchain / full coverage", std::bind(&tests::blockchain_full_coverage, (vector<account_ref>*)nullptr) },
			{ "blockchain / verification", &tests::blockchain_verification },
			{ "blockchain / bridge coverage", std::bind(&tests::blockchain_bridge_coverage, (vector<account_ref>*)nullptr) },
			{ "blockchain / verification", &tests::blockchain_verification },
			{ "blockchain / partial coverage", std::bind(&tests::blockchain_partial_coverage, (vector<account_ref>*)nullptr) },
			{ "blockchain / verification", &tests::blockchain_verification },
			{ "blockchain / gas estimation", &tests::blockchain_gas_estimation }
		};

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

		queue->stop();
		exit_code = 0;
	}
	else if (test == "integration")
	{
		/* test case runner for superchain testing */
		auto* queue = schedule::get();
		queue->start(schedule::desc());

		auto path = args.get("test-path");
		VI_PANIC(!path.empty(), "must provide a \"test-path\" flag (string)");
		auto data = schema::from_json(os::file::read_as_string(path).expect("failed to find the file")).expect("failed to parse the file");
		auto network = data->get_var("net").get_blob();
		auto token = data->get_var("tok").get_blob();
		auto contract = data->get_var("ctn").get_blob();
		auto url = data->get_var("url").get_blob();
		auto from_address = data->get_var("pay").get_blob();
		auto to_address = data->get_var("out").get_blob();
		auto amount = data->get_var("amt").get_decimal();
		auto fee = data->get_var("fee").get_decimal();
		VI_PANIC(!network.empty(), "network should be set");
		VI_PANIC(!url.empty(), "url should be set");
		VI_PANIC(amount.is_positive(), "amount should be positive");
		VI_PANIC(fee.is_positive(), "fee should be positive");

		tests::blockchain_integration_coverage(algorithm::asset::id_of(network, token, contract), url, from_address, to_address, amount, fee, [&]()
		{
			term->write("block number with tx: ");
			return from_string<uint64_t>(term->read(128)).expect("failed to parse the block number");
		}, [&](const std::string_view& from_account, const std::string_view& to_account, const algorithm::asset_id& asset, const decimal& value)
		{
			auto eth_chain = superchain::bridge::get()->get_network(algorithm::asset::id_of("ETH"));
			auto eth_value = "0x" + eth_chain->to_baseline_value(value).to_string(16);
			term->fwrite_line(
				"incoming transaction integration:\n"
				" - account %.*s sends %s (%s) %s to account %.*s", (int)from_account.size(), from_account.data(), value.to_string().c_str(), eth_value.c_str(), algorithm::asset::name_of(asset).c_str(), (int)to_account.size(), to_account.data());
		});

		queue->stop();
		exit_code = 0;
	}
	else if (test == "script")
		exit_code = entrypoints::script(args);
	else if (test == "node")
		exit_code = entrypoints::node(args);

	VI_PANIC(exit_code != bad_entrypoint_exit_code, "must provide a \"test\" flag (string in [consensus, benchmark, regression, integration] or in [script, node])");
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