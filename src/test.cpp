#include "tangent/entrypoints.hpp"
#include "tangent/storage/superchainstate.h"
#include "tangent/storage/mempoolstate.h"
#include "tangent/policy/compositions.h"
#include <vitex/vitex.h>
#include <sstream>
#define TEST_BLOCK(x, y, z) tester::new_block_from_generator(data, users, x, #x, y, z)
#define TEST_BLOCK_FAULT(x, y, z) tester::new_block_from_generator(data, users, x, #x, y, z, true)

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
	static ledger::block new_block_from_generator(format::tree* results, vector<account_ref>& users, std::function<void(vector<uptr<ledger::transaction>>&, vector<account_ref>&)>&& test_case, const std::string_view& test_case_call, const std::string_view& state_root_hash, uint64_t block_number, bool causes_fault = false)
	{
		for (auto& user : users)
			user.nonce = user.wallet.get_latest_nonce().or_else(0);

		vector<uptr<ledger::transaction>> transactions;
		test_case(transactions, users);

		auto block = new_block_from_list(results, users, std::move(transactions), causes_fault);
		auto hash = algorithm::encoding::encode_0xhex256(block.state_root);
		if (results != nullptr)
			console::get()->fwrite_line("TEST_BLOCK%s(%s, \"%s\", %" PRIu64 ");", causes_fault ? "_FAULT" : "", test_case_call.data(), hash.c_str(), block.number);

		VI_PANIC(state_root_hash.empty() || state_root_hash == hash, "block state root deviation");
		VI_PANIC(!block_number || block_number == block.number, "block number deviation");
		return block;
	}
	static ledger::block new_block_from_one(format::tree* results, vector<account_ref>& users, uptr<ledger::transaction>&& transaction, bool causes_fault = false)
	{
		auto transactions = vector<uptr<ledger::transaction>>();
		transactions.push_back(std::move(transaction));
		return new_block_from_list(results, users, std::move(transactions), causes_fault);
	}
	static ledger::block new_block_from_list(format::tree* results, vector<account_ref>& users, vector<uptr<ledger::transaction>>&& transactions, bool causes_fault = false)
	{
		ledger::solver_context solver;
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

		uint64_t priority = solver.apply_validator_state([&users](size_t index) { return index < users.size() ? &users[index].wallet : nullptr; }).or_else(std::numeric_limits<uint64_t>::max());
		VI_PANIC(priority == 0, "block proposal not allowed");
		ledger::solver_context::sort_transaction_list(transactions);
		if (!solver.try_include_transactions(std::move(transactions)))
			VI_PANIC(false, "empty block not allowed");

		auto proposal = solver.evaluate_block(nullptr).expect("block evaluation failed");
		solver.solve_block(proposal).expect("block solution failed");
		if (results != nullptr)
			solver.verify_block(proposal).expect("block verification failed");

		transactions = vector<uptr<ledger::transaction>>();
		solver.checkpoint_block(proposal).expect("block checkpoint failed");
		if (results != nullptr)
			results->push(proposal.as_tree());

		vector<ledger::wallet> validators;
		validators.reserve(users.size());
		for (auto& [user, user_nonce] : users)
			validators.push_back(user);

		auto dispatcher = consensus::local_dispatcher_context(validators);
		dispatcher.dispatch_sync(proposal.block.number);
		for (auto& [runner_wallet, transaction] : dispatcher.outputs)
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
		for (auto& transaction : dispatcher.errors)
			VI_PANIC(causes_fault, "%s", transaction.second.c_str());
		
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
		callback();
	}
};

struct generators
{
	static void transfer_stage_1(vector<uptr<ledger::transaction>>& transactions, vector<account_ref>& users)
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
	static void transfer_stage_2(vector<uptr<ledger::transaction>>& transactions, vector<account_ref>& users)
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
	static void transfer_custom(vector<uptr<ledger::transaction>>& transactions, vector<account_ref>& users, size_t user_id, const algorithm::asset_id& asset, const std::string_view& address, const decimal& value)
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
	static void rollup_stage_1(vector<uptr<ledger::transaction>>& transactions, vector<account_ref>& users)
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
	static void deploy_stage_1(vector<uptr<ledger::transaction>>& transactions, vector<account_ref>& users, vector<algorithm::pubkeyhash_t>* contracts)
	{
		auto& [user1, user1_nonce] = users[0];
		string token_program = *algorithm::encoding::unpack_program(codec::base64_decode("eNq1VduOmzAQfd5I+YdRHirQ7qKqfcsmVf8kcmCIrBqbGjtpVPXf6yvYIShadfsGZ4a5nDMz1IwMAyjxA/lhUEKSE65Xv9erJ9I0Eo2pwZ6JK8q3BKsFV5LUKsVIXQvNHTQoSfkJOOkweR2u3VEwC0gk7OuXzzDovmdXg/xZr9arOqnEROdDizIvpZWiS1MqkUY7E6YxBjsTeTVJd1lj33z0N+uQGWxDpkpdq6LvtPr+4gHwlX+iPBQ/x22PEQ1lWZg0HeURDwVa3NVY+q4k/tRUYuGwqhcDVfSMRfkCG8oYnggD0aMkigoOr4Es6LSJeESI/pvScpB3w/FyiJ0+jS9VVBL2oH5tt5bNosxdorDBRYlbh6CysbsWc6Mlw1ii7pPBs2dM0wwkRt/YfhTQd2MDJX1EuJLYxioqU4EqJjiKlCAudunHRGnJJ5uflHzcID7kY5AIq8QDVdNZnRH9Tsmd24LiWSjY7eFIGOE1HkRbcM0MCzatiexnNVThMHiGzRbuJaR80G1La4pG4hDQp7MfVkdD4B26ffteuCVJRp9xWEfO8Yz+bLiHKhAXd92DSlguxQT4tpOZCfLGYEbaeBdcRZmeDxZyNmewT4VcEGt65kKBeemoUthsPlj45WV3DE3DPd+w5w9csUnzQPxs/GahylwWN0zvkeV/LM3tpTAxPTOBsovJAJo3KFsmLlBszO5kCzU7NXa5YAczR9+RtZb/quPrYx1vfsqzQxTVfbjRS+ouaDq59U7Teyc0fhrVdQnGgqYItaDc/oJMcbMSyzI935FCylsRE+fhs6v/F6kiAY0="));
		string bridge_program = *algorithm::encoding::unpack_program(codec::base64_decode("eNpljssKgzAURNcN5B+Ci2JApLQ7a8U/CWm8FmlM5ObGtpT+ex/ahbgdZs6cUeOjc5dSNw1CCJUgfwWntDE+Ojpyxtnou0YY7wJhNJQOfaQ6mwIxz7adEw5uajGWnD052ywycVr3PicvzhC0Pex34qytdgaUbxVBoKmaDr+7ekYiUES3VM0R2txoa8uZVKXJmvkHrf1lkgm6F0WLvk+l/Eq9AUJwYpA="));

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
	static void deploy_stage_2(vector<uptr<ledger::transaction>>& transactions, vector<account_ref>& users, vector<algorithm::pubkeyhash_t>* contracts)
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
	static void call_stage_1(vector<uptr<ledger::transaction>>& transactions, vector<account_ref>& users, vector<algorithm::pubkeyhash_t>* contracts)
	{
		auto& [user1, user1_nonce] = users[0];
		auto& [user2, user2_nonce] = users[1];
		auto* call1 = memory::init<transactions::call>();
		call1->call_to(contracts->at(0), "transfer", { format::variable(user2.public_key_hash.view()), format::variable(decimal(1234u)) });
		call1->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(call1);

		auto* call2 = memory::init<transactions::call>();
		call2->call_to(contracts->at(0), "info", { });
		call2->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(call2);

		auto* call3 = memory::init<transactions::call>();
		call3->call_to(contracts->at(2), "transfer", { format::variable(user1.public_key_hash.view()), format::variable(decimal(4321u)) });
		call3->sign(user2.secret_key, user2_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(call3);

		auto* call4 = memory::init<transactions::call>();
		call4->call_to(contracts->at(2), "info", { });
		call4->sign(user2.secret_key, user2_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(call4);

		auto* call5 = memory::init<transactions::call>();
		call5->call_to(contracts->at(1), "balance_of_test_token", { });
		call5->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(call5);

		auto* call6 = memory::init<transactions::call>();
		call6->call_to(contracts->at(3), "balance_of_test_token", { });
		call6->sign(user2.secret_key, user2_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(call6);

		auto* call7 = memory::init<transactions::call>();
		call7->call_to(contracts->at(4), "test_module", { });
		call7->set_gas(decimal::zero(), 500000);
		call7->sign(user2.secret_key, user2_nonce++);
		transactions.push_back(call7);
	}
	static void setup_stage_0(vector<uptr<ledger::transaction>>& transactions, vector<account_ref>& users)
	{
		auto& [user1, user1_nonce] = users[0];
		auto* setup_user1 = memory::init<transactions::setup>();
		setup_user1->allocate_production_stake(decimal::zero());
		setup_user1->allocate_attestation_stake(algorithm::asset::id_of("ETH"), decimal::zero());
		setup_user1->configure_attestation_security(algorithm::asset::id_of("ETH"), protocol::now().policy.participation.min_per_account, decimal::zero(), true, true);
		setup_user1->configure_attestation_reward(algorithm::asset::id_of("ETH"), 0, 0.001);
		setup_user1->allocate_attestation_stake(algorithm::asset::id_of("TRX"), decimal::zero());
		setup_user1->configure_attestation_security(algorithm::asset::id_of("TRX"), protocol::now().policy.participation.min_per_account, decimal::zero(), true, true);
		setup_user1->configure_attestation_reward(algorithm::asset::id_of("TRX"), 0, 20);
		setup_user1->allocate_attestation_stake(algorithm::asset::id_of("BTC"), decimal::zero());
		setup_user1->configure_attestation_security(algorithm::asset::id_of("BTC"), protocol::now().policy.participation.min_per_account, decimal::zero(), true, true);
		setup_user1->configure_attestation_reward(algorithm::asset::id_of("BTC"), 0, 0.0005);
		setup_user1->allocate_participation_stake(decimal::zero());
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
	static void setup_stage_1(vector<uptr<ledger::transaction>>& transactions, vector<account_ref>& users)
	{
		auto& [user1, user1_nonce] = users[0];
		auto& [user2, user2_nonce] = users[1];
		auto* setup_user1 = memory::init<transactions::setup>();
		setup_user1->allocate_production_stake(decimal::zero());
		setup_user1->allocate_attestation_stake(algorithm::asset::id_of("XRP"), decimal::zero());
		setup_user1->configure_attestation_reward(algorithm::asset::id_of("XRP"), 0, 0.001);
		setup_user1->configure_attestation_security(algorithm::asset::id_of("XRP"), protocol::now().policy.participation.min_per_account, decimal::zero(), true, true);
		setup_user1->allocate_participation_stake(decimal::zero());
		setup_user1->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(setup_user1);

		auto* setup_user2 = memory::init<transactions::setup>();
		setup_user2->allocate_attestation_stake(algorithm::asset::id_of("ETH"), decimal::zero());
		setup_user2->configure_attestation_reward(algorithm::asset::id_of("ETH"), 0.0012, 0.0012);
		setup_user2->configure_attestation_security(algorithm::asset::id_of("ETH"), protocol::now().policy.participation.min_per_account, decimal::zero(), true, true);
		setup_user2->allocate_attestation_stake(algorithm::asset::id_of("XRP"), decimal::zero());
		setup_user2->configure_attestation_reward(algorithm::asset::id_of("XRP"), 1.0, 1.0);
		setup_user2->configure_attestation_security(algorithm::asset::id_of("XRP"), protocol::now().policy.participation.min_per_account, decimal::zero(), true, true);
		setup_user2->allocate_attestation_stake(algorithm::asset::id_of("BTC"), decimal::zero());
		setup_user2->configure_attestation_reward(algorithm::asset::id_of("BTC"), 0.000025, 0.000025);
		setup_user2->configure_attestation_security(algorithm::asset::id_of("BTC"), protocol::now().policy.participation.min_per_account, decimal::zero(), true, true);
		setup_user2->allocate_participation_stake(decimal::zero());
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
	static void setup_custom(vector<uptr<ledger::transaction>>& transactions, vector<account_ref>& users, size_t user_id, int8_t tx_attestation, int8_t mpc_participation)
	{
		auto& [user1, user1_nonce] = users[user_id];
		auto* setup_user1 = memory::init<transactions::setup>();
		if (tx_attestation != 0)
		{
			if (tx_attestation > 0)
			{
				setup_user1->allocate_attestation_stake(algorithm::asset::id_of("ETH"), decimal::zero());
				setup_user1->allocate_attestation_stake(algorithm::asset::id_of("XRP"), decimal::zero());
				setup_user1->allocate_attestation_stake(algorithm::asset::id_of("BTC"), decimal::zero());
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
	static void route_stage_0(vector<uptr<ledger::transaction>>& transactions, vector<account_ref>& users)
	{
		auto& [user1, user1_nonce] = users[0];
		auto* route_bitcoin = memory::init<transactions::route>();
		route_bitcoin->set_asset("BTC");
		route_bitcoin->set_routing_address("mmtubFoJvXrBuBUQFf1RrowXUbsiPDYnYS");
		route_bitcoin->set_manager(user1.public_key_hash);
		route_bitcoin->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(route_bitcoin);

		auto* route_ethereum = memory::init<transactions::route>();
		route_ethereum->set_asset("ETH");
		route_ethereum->set_routing_address("0xCa0dfDdBb1cBD7B5A08E9173D9bbE5722138d4d5");
		route_ethereum->set_manager(user1.public_key_hash);
		route_ethereum->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(route_ethereum);

		auto* route_tron = memory::init<transactions::route>();
		route_tron->set_asset("TRX");
		route_tron->set_routing_address("TFwBey8L5swmhRGEQSCnULT7ad68KFJe6L");
		route_tron->set_manager(user1.public_key_hash);
		route_tron->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(route_tron);
	}
	static void route_stage_1(vector<uptr<ledger::transaction>>& transactions, vector<account_ref>& users)
	{
		auto& [user1, user1_nonce] = users[0];
		auto& [user2, user2_nonce] = users[1];
		auto* route_ethereum = memory::init<transactions::route>();
		route_ethereum->set_asset("ETH");
		route_ethereum->set_manager(user2.public_key_hash);
		route_ethereum->sign(user2.secret_key, user2_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(route_ethereum);

		auto* route_ripple1 = memory::init<transactions::route>();
		route_ripple1->set_asset("XRP");
		route_ripple1->set_routing_address("rUBqz2JiRCT3gYZBnm28y5ME7e5UpSm2ok");
		route_ripple1->set_manager(user1.public_key_hash);
		route_ripple1->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(route_ripple1);

		auto* route_ripple2 = memory::init<transactions::route>();
		route_ripple2->set_asset("XRP");
		route_ripple2->set_manager(user2.public_key_hash);
		route_ripple2->sign(user2.secret_key, user2_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(route_ripple2);
	}
	static void route_stage_2(vector<uptr<ledger::transaction>>& transactions, vector<account_ref>& users)
	{
		auto& [user1, user1_nonce] = users[0];
		auto& [user2, user2_nonce] = users[1];
		auto* route_ethereum = memory::init<transactions::route>();
		route_ethereum->set_asset("ETH");
		route_ethereum->set_routing_address("0xCa0dfDdBb1cBD7B5A08E9173D9bbE5722138d4d5");
		route_ethereum->set_manager(user2.public_key_hash);
		route_ethereum->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(route_ethereum);

		auto* route_ripple = memory::init<transactions::route>();
		route_ripple->set_asset("XRP");
		route_ripple->set_manager(user2.public_key_hash);
		route_ripple->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(route_ripple);

		auto* route_bitcoin = memory::init<transactions::route>();
		route_bitcoin->set_asset("BTC");
		route_bitcoin->set_routing_address("mmtubFoJvXrBuBUQFf1RrowXUbsiPDYnYS");
		route_bitcoin->set_manager(user2.public_key_hash);
		route_bitcoin->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(route_bitcoin);
	}
	static void attestate_stage_0(vector<uptr<ledger::transaction>>& transactions, vector<account_ref>& users)
	{
		auto& [user1, user1_nonce] = users[0];
		auto executor = ledger::executor_context(nullptr);
		auto owner_addresses = *executor.get_witness_accounts_by_purpose(user1.public_key_hash, states::witness_account::account_type::bridge, 0, 128);
		auto address_bitcoin = std::find_if(owner_addresses.begin(), owner_addresses.end(), [](states::witness_account& item) { return item.asset == algorithm::asset::id_of("BTC"); });
		auto address_ethereum = std::find_if(owner_addresses.begin(), owner_addresses.end(), [](states::witness_account& item) { return item.asset == algorithm::asset::id_of("ETH"); });
		auto address_tron = std::find_if(owner_addresses.begin(), owner_addresses.end(), [](states::witness_account& item) { return item.asset == algorithm::asset::id_of("TRX"); });
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
	static void attestate_stage_1(vector<uptr<ledger::transaction>>& transactions, vector<account_ref>& users)
	{
		auto& [user1, user1_nonce] = users[0];
		auto& [user2, user2_nonce] = users[1];
		auto executor = ledger::executor_context(nullptr);
		auto owner_addresses = *executor.get_witness_accounts_by_purpose(user1.public_key_hash, states::witness_account::account_type::bridge, 0, 128);
		auto manager_addresses = *executor.get_witness_accounts_by_purpose(user2.public_key_hash, states::witness_account::account_type::bridge, 0, 128);
		auto address_ethereum = std::find_if(manager_addresses.begin(), manager_addresses.end(), [&](states::witness_account& item) { return item.manager != user1.public_key_hash && item.asset == algorithm::asset::id_of("ETH"); });
		auto address_ripple = std::find_if(owner_addresses.begin(), owner_addresses.end(), [&](states::witness_account& item) { return item.manager != user1.public_key_hash && item.asset == algorithm::asset::id_of("XRP"); });
		auto address_bitcoin = std::find_if(owner_addresses.begin(), owner_addresses.end(), [&](states::witness_account& item) { return item.manager != user1.public_key_hash && item.asset == algorithm::asset::id_of("BTC"); });
		VI_PANIC(address_ethereum != manager_addresses.end(), "ethereum bridge address not found");
		VI_PANIC(address_ripple != owner_addresses.end(), "ripple bridge address not found");
		VI_PANIC(address_bitcoin != owner_addresses.end(), "bitcoin bridge address not found");

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
	}
	static void migrate_stage_1(vector<uptr<ledger::transaction>>& transactions, vector<account_ref>& users)
	{
		auto& [user1, user1_nonce] = users[0];
		auto& [user2, user2_nonce] = users[1];
		auto* withdrawal_ethereum_token = memory::init<transactions::withdraw>();
		withdrawal_ethereum_token->set_asset("ETH", "USDT", "0xdAC17F958D2ee523a2206206994597C13D831ec7");
		withdrawal_ethereum_token->set_manager(user2.public_key_hash);
		withdrawal_ethereum_token->set_to("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", 1);
		withdrawal_ethereum_token->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(withdrawal_ethereum_token);
	}
	static void migrate_stage_2(vector<uptr<ledger::transaction>>& transactions, vector<account_ref>& users)
	{
		for (size_t i = protocol::now().policy.participation.min_per_account + 1; i < protocol::now().policy.participation.max_per_account; i++)
		{
			users.push_back(account_ref(ledger::wallet::from_seed(stringify::text("00000%i", (int)i)), 0));
			auto& [user_n, user_n_nonce] = users[i];
			auto* setup_user_n = memory::init<transactions::setup>();
			setup_user_n->allocate_participation_stake(decimal::zero());
			setup_user_n->sign(user_n.secret_key, user_n_nonce++, decimal::zero()).expect("pre-validation failed");
			transactions.push_back(setup_user_n);
		}

		auto chain = storages::chainstate();
		auto block_number = chain.get_latest_block_number().expect("must have parent block");
		auto targets = chain.get_transactions_by_number(block_number, 0, 1).expect("must have last transaction");
		VI_PANIC(!targets.empty(), "must have last transaction");

		auto& transaction = targets.front();
		VI_PANIC(transaction->as_type() == transactions::broadcast::as_instance_type(), "must have withdrawal finalization as last transaction");

		auto* withdrawal_finalization = (transactions::broadcast*)*transaction;
		VI_PANIC(!withdrawal_finalization->proof, "withdrawal finalized must be failed (synthetic error)");

		auto& [user2, user2_nonce] = users[1];
		auto executor = ledger::executor_context(nullptr);
		auto accounts = executor.get_bridge_accounts(user2.public_key_hash, 0, 128).expect("user 2 must have bridge accounts");
		auto it = std::find_if(accounts.begin(), accounts.end(), [&](const states::bridge_account& item) { return item.asset == algorithm::asset::base_id_of(withdrawal_finalization->asset) && !item.group.empty(); });
		VI_PANIC(it != accounts.end(), "user 2 must have at least one bridge account under management corresponding to failed withdrawal");
		auto old_participant = it->group.begin();
		if (*old_participant == user2.public_key_hash)
			++old_participant;

		auto* setup_user2 = memory::init<transactions::setup>();
		setup_user2->migrate_participant(withdrawal_finalization->as_hash(), *old_participant);
		setup_user2->sign(user2.secret_key, user2_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(setup_user2);
	}
	static void migrate_stage_3(vector<uptr<ledger::transaction>>& transactions, vector<account_ref>& users)
	{
		auto& [user2, user2_nonce] = users[1];
		auto* setup_user2 = memory::init<transactions::setup>();
		setup_user2->disable_participation();
		setup_user2->sign(user2.secret_key, user2_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(setup_user2);
	}
	static void withdraw_stage_1(vector<uptr<ledger::transaction>>& transactions, vector<account_ref>& users)
	{
		auto& [user1, user1_nonce] = users[0];
		auto& [user2, user2_nonce] = users[1];
		auto executor = ledger::executor_context(nullptr);
		auto* withdrawal_ethereum_token = memory::init<transactions::withdraw>();
		withdrawal_ethereum_token->set_asset("ETH", "USDT", "0xdAC17F958D2ee523a2206206994597C13D831ec7");
		withdrawal_ethereum_token->set_manager(user2.public_key_hash);
		withdrawal_ethereum_token->set_to("0xbeefdeadbeefdeadbeefdeadbeefdeadbeefdead", executor.get_account_balance(algorithm::asset::id_of("ETH", "USDT", "0xdAC17F958D2ee523a2206206994597C13D831ec7"), user1.public_key_hash).expect("user balance not valid").get_balance());
		withdrawal_ethereum_token->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(withdrawal_ethereum_token);
	}
	static void withdraw_stage_2(vector<uptr<ledger::transaction>>& transactions, vector<account_ref>& users)
	{
		auto& [user1, user1_nonce] = users[0];
		auto& [user2, user2_nonce] = users[1];
		auto* withdraw_ripple = memory::init<transactions::withdraw>();
		withdraw_ripple->set_asset("XRP");
		withdraw_ripple->set_manager(user2.public_key_hash);
		withdraw_ripple->sign(user2.secret_key, user2_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(withdraw_ripple);
	}
	static void withdraw_stage_3(vector<uptr<ledger::transaction>>& transactions, vector<account_ref>& users)
	{
		auto& [user1, user1_nonce] = users[0];
		auto& [user2, user2_nonce] = users[1];
		auto chain = storages::chainstate();
		auto results = chain.get_transactions_by_owner(chain.get_latest_block_number().or_else(1), user2.public_key_hash, -1, 0, 16);
		for (auto& transaction : *results)
		{
			if (transaction->as_type() != transactions::broadcast::as_instance_type())
				continue;

			auto* broadcast = (transactions::broadcast*)*transaction;
			if (!broadcast->proof || broadcast->proof->prepared.outputs.size() != 1 || broadcast->proof->prepared.outputs.front().link.address != "0xbeefdeadbeefdeadbeefdeadbeefdeadbeefdead")
				continue;

			auto* anticast_ethereum_token = memory::init<transactions::anticast>();
			anticast_ethereum_token->asset = broadcast->asset;
			anticast_ethereum_token->set_protest(broadcast->as_hash());
			anticast_ethereum_token->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
			transactions.push_back(anticast_ethereum_token);
		}
	}
	static void withdraw_stage_4(vector<uptr<ledger::transaction>>& transactions, vector<account_ref>& users)
	{
		auto& [user1, user1_nonce] = users[0];
		auto& [user2, user2_nonce] = users[1];
		auto executor = ledger::executor_context(nullptr);
		auto* withdrawal_ethereum_token = memory::init<transactions::withdraw>();
		withdrawal_ethereum_token->set_asset("ETH", "USDT", "0xdAC17F958D2ee523a2206206994597C13D831ec7");
		withdrawal_ethereum_token->set_manager(user2.public_key_hash);
		withdrawal_ethereum_token->set_to("0xCa0dfDdBb1cBD7B5A08E9173D9bbE5722138d4d5", executor.get_account_balance(algorithm::asset::id_of("ETH", "USDT", "0xdAC17F958D2ee523a2206206994597C13D831ec7"), user1.public_key_hash).expect("user balance not valid").get_balance());
		withdrawal_ethereum_token->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(withdrawal_ethereum_token);
	}
	static void withdraw_stage_5(vector<uptr<ledger::transaction>>& transactions, vector<account_ref>& users)
	{
		auto& [user1, user1_nonce] = users[0];
		auto& [user2, user2_nonce] = users[1];
		auto executor = ledger::executor_context(nullptr);
		auto validator_attestation_ethereum = executor.get_validator_attestation(algorithm::asset::id_of("ETH"), user2.public_key_hash).or_else(states::validator_attestation(algorithm::pubkeyhash_t(), 0, nullptr));
		auto* withdrawal_ethereum = memory::init<transactions::withdraw>();
		withdrawal_ethereum->set_asset("ETH");
		withdrawal_ethereum->set_manager(user2.public_key_hash);
		withdrawal_ethereum->set_to("0xCa0dfDdBb1cBD7B5A08E9173D9bbE5722138d4d5", executor.get_account_balance(algorithm::asset::id_of("ETH"), user1.public_key_hash).expect("user balance not valid").get_balance() - validator_attestation_ethereum.outgoing_fee);
		withdrawal_ethereum->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(withdrawal_ethereum);

		auto validator_attestation_ripple = executor.get_validator_attestation(algorithm::asset::id_of("XRP"), user1.public_key_hash).or_else(states::validator_attestation(algorithm::pubkeyhash_t(), 0, nullptr));
		auto* withdrawal_ripple = memory::init<transactions::withdraw>();
		withdrawal_ripple->set_asset("XRP");
		withdrawal_ripple->set_manager(user1.public_key_hash);
		withdrawal_ripple->set_to("rUBqz2JiRCT3gYZBnm28y5ME7e5UpSm2ok", executor.get_account_balance(algorithm::asset::id_of("XRP"), user1.public_key_hash).expect("user balance not valid").get_balance() - validator_attestation_ripple.outgoing_fee);
		withdrawal_ripple->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(withdrawal_ripple);

		auto validator_attestation_bitcoin = executor.get_validator_attestation(algorithm::asset::id_of("BTC"), user2.public_key_hash).or_else(states::validator_attestation(algorithm::pubkeyhash_t(), 0, nullptr));
		auto* withdrawal_bitcoin = memory::init<transactions::withdraw>();
		withdrawal_bitcoin->set_asset("BTC");
		withdrawal_bitcoin->set_manager(user2.public_key_hash);
		withdrawal_bitcoin->set_to("mmtubFoJvXrBuBUQFf1RrowXUbsiPDYnYS", executor.get_account_balance(algorithm::asset::id_of("BTC"), user1.public_key_hash).expect("user balance not valid").get_balance() - validator_attestation_bitcoin.outgoing_fee);
		withdrawal_bitcoin->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(withdrawal_bitcoin);
	}
	static void withdraw_stage_6(vector<uptr<ledger::transaction>>& transactions, vector<account_ref>& users)
	{
		auto& [user1, user1_nonce] = users[0];
		auto& [user2, user2_nonce] = users[1];
		auto executor = ledger::executor_context(nullptr);
		auto validator_attestation_ethereum = executor.get_validator_attestation(algorithm::asset::id_of("ETH"), user2.public_key_hash).or_else(states::validator_attestation(algorithm::pubkeyhash_t(), 0, nullptr));
		auto* withdrawal_ethereum = memory::init<transactions::withdraw>();
		withdrawal_ethereum->set_asset("ETH");
		withdrawal_ethereum->set_manager(user2.public_key_hash);
		withdrawal_ethereum->set_to("0x89a0181659bd280836A2d33F57e3B5Dfa1a823CE", executor.get_account_balance(algorithm::asset::id_of("ETH"), user2.public_key_hash).expect("user balance not valid").get_balance() - validator_attestation_ethereum.outgoing_fee);
		withdrawal_ethereum->sign(user2.secret_key, user2_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(withdrawal_ethereum);

		auto validator_attestation_ripple = executor.get_validator_attestation(algorithm::asset::id_of("XRP"), user1.public_key_hash).or_else(states::validator_attestation(algorithm::pubkeyhash_t(), 0, nullptr));
		auto* withdrawal_ripple = memory::init<transactions::withdraw>();
		withdrawal_ripple->set_asset("XRP");
		withdrawal_ripple->set_manager(user1.public_key_hash);
		withdrawal_ripple->set_to("rJGb4etn9GSwNHYVu7dNMbdiVgzqxaTSUG", executor.get_account_balance(algorithm::asset::id_of("XRP"), user2.public_key_hash).expect("user balance not valid").get_balance() - validator_attestation_ripple.outgoing_fee);
		withdrawal_ripple->sign(user2.secret_key, user2_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(withdrawal_ripple);

		auto validator_attestation_bitcoin = executor.get_validator_attestation(algorithm::asset::id_of("BTC"), user2.public_key_hash).or_else(states::validator_attestation(algorithm::pubkeyhash_t(), 0, nullptr));
		auto* withdrawal_bitcoin = memory::init<transactions::withdraw>();
		withdrawal_bitcoin->set_asset("BTC");
		withdrawal_bitcoin->set_manager(user2.public_key_hash);
		withdrawal_bitcoin->set_to("bcrt1p2w7gkghj7arrjy4c45kh7450458hr8dv9pu9576lx08uuh4je7eqgskm9v", executor.get_account_balance(algorithm::asset::id_of("BTC"), user2.public_key_hash).expect("user balance not valid").get_balance() - validator_attestation_bitcoin.outgoing_fee);
		withdrawal_bitcoin->sign(user2.secret_key, user2_nonce++, decimal::zero()).expect("pre-validation failed");
		transactions.push_back(withdrawal_bitcoin);
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
		tester::new_serialization_comparison<ledger::receipt>(data);
		tester::new_serialization_comparison<ledger::wallet>(data);
		tester::new_serialization_comparison<ledger::node>(data);
		tester::new_serialization_comparison<ledger::block_transaction>(data);
		tester::new_serialization_comparison<ledger::block_header>(data);
		tester::new_serialization_comparison<ledger::block>(data);
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
		tester::new_serialization_comparison<states::validator_participation_ref>(data, owner, states::validator_participation_ref::ref_value(), block_number++);
		tester::new_serialization_comparison<states::validator_attestation>(data, owner, asset, block_number++);
		tester::new_serialization_comparison<states::validator_attestation_reward>(data, owner, asset, block_number++);
		tester::new_serialization_comparison<states::bridge_balance>(data, owner, asset, block_number++);
		tester::new_serialization_comparison<states::bridge_account>(data, owner, asset, owner, block_number++);
		tester::new_serialization_comparison<states::witness_program>(data, std::string_view(), block_number++);
		tester::new_serialization_comparison<states::witness_event>(data, asset, block_number++);
		tester::new_serialization_comparison<states::witness_account>(data, owner, asset, address_map(), block_number++);
		tester::new_serialization_comparison<states::witness_transaction>(data, asset, std::string_view(), block_number++);
		tester::new_serialization_comparison<transactions::transfer>(data);
		tester::new_serialization_comparison<transactions::deploy>(data);
		tester::new_serialization_comparison<transactions::call>(data);
		tester::new_serialization_comparison<transactions::rollup>(data);
		tester::new_serialization_comparison<transactions::setup>(data);
		tester::new_serialization_comparison<transactions::migrate>(data);
		tester::new_serialization_comparison<transactions::route>(data);
		tester::new_serialization_comparison<transactions::bind>(data);
		tester::new_serialization_comparison<transactions::withdraw>(data);
		tester::new_serialization_comparison<transactions::broadcast>(data);
		tester::new_serialization_comparison<transactions::attestate>(data);

		auto* term = console::get();
		term->write_line(data.as_json(true));
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
			auto proof = algorithm::wesolowski::evaluate(difficulty, message);

			auto evaluation_time = evaluation_time_point.elapsed();
			auto verification_time_point = date_time();
			bool proven = algorithm::wesolowski::verify(difficulty, message, proof);

			auto message_copy = string(message);
			message_copy.back() = '?';
			bool not_forged = !algorithm::wesolowski::verify(difficulty, message_copy, proof);

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

		uint64_t baseline = protocol::now().policy.pow.difficulty;
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
		vector<uptr<ledger::transaction>> transactions;
		vector<account_ref> users =
		{
			account_ref(wallet, 1),
			account_ref(ledger::wallet::from_seed(), 1)
		};

		auto tx = transactions::transfer();
		tx.gas_limit = ledger::block::get_transaction_gas_limit();
		tx.set_to(users[1].wallet.public_key_hash, decimal("13.539899"));
		VI_PANIC(tx.sign(users[0].wallet.secret_key, users[0].nonce++), "authentication failed");

		auto tx_blob = tx.as_message().data;
		auto tx_body = format::ro_stream(tx_blob);
		auto tx_copy = uptr<ledger::transaction>(transactions::resolver::from_stream(tx_body));
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
		auto* server = superchain::server_node::get();
		auto user = ledger::wallet::from_seed("0000000");
		for (auto& asset : server->get_assets())
		{
			uint8_t seed[] = "123456";
			auto wallet = *server->compute_wallet(asset, seed, sizeof(seed) - 1);
			auto info = wallet.as_tree();
			info.set("asset", algorithm::asset::serialize(asset));
			term->write_line(info.as_json(true));
		}
	}
	/* multi-party wallet keypair and signature generation */
	static void cryptography_multichain_mpc()
	{
		auto* term = console::get();
		vector<participant_ref> participants;
		participants.resize(protocol::now().policy.participation.min_per_account);

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
			auto mpc_chosen_phase_participant = participants.begin() + (size_t)(crypto::random() % (uint64_t)participants.size());
			auto mpc_phase_participants = vector<participant_ref>();
			auto mpc_timeline = vector<string>();
			auto mpc_state = algorithm::composition::make_public_key_compositor(alg, message_hash, sizeof(message_hash), (uint16_t)participants.size()).expect("failed to make the state");
			while (true)
			{
				auto time = date_time();
				auto next = mpc_phase_participants.end();
				switch (mpc_state->next_phase())
				{
					case algorithm::composition::phase::any_input_after_reset:
						mpc_phase_participants = participants;
						next = mpc_phase_participants.begin();
						next = mpc_phase_participants.size() > 1 && next->seed == mpc_chosen_phase_participant->seed ? next + 1 : next;
						if (!mpc_timeline.empty())
							mpc_timeline.push_back("advance");
						mpc_timeline.push_back(stringify::text("random(%i)", 1 + (int)std::distance(participants.begin(), std::find_if(participants.begin(), participants.end(), [&](const participant_ref& item) { return item.seed == next->seed; }))));
						break;
					case algorithm::composition::phase::any_input:
						next = mpc_phase_participants.begin();
						next = mpc_phase_participants.size() > 1 && next->seed == mpc_chosen_phase_participant->seed ? next + 1 : next;
						mpc_timeline.push_back(stringify::text("random(%i)", 1 + (int)std::distance(participants.begin(), std::find_if(participants.begin(), participants.end(), [&](const participant_ref& item) { return item.seed == next->seed; }))));
						break;
					case algorithm::composition::phase::chosen_input_after_reset:
						mpc_phase_participants = participants;
						next = std::find_if(mpc_phase_participants.begin(), mpc_phase_participants.end(), [&](const participant_ref& item) { return item.seed == mpc_chosen_phase_participant->seed; });
						if (!mpc_timeline.empty())
							mpc_timeline.push_back("advance");
						mpc_timeline.push_back(stringify::text("chosen(%i)", 1 + (int)std::distance(participants.begin(), std::find_if(participants.begin(), participants.end(), [&](const participant_ref& item) { return item.seed == next->seed; }))));
						break;
					case algorithm::composition::phase::chosen_input:
						next = std::find_if(mpc_phase_participants.begin(), mpc_phase_participants.end(), [&](const participant_ref& item) { return item.seed == mpc_chosen_phase_participant->seed; });
						mpc_timeline.push_back(stringify::text("chosen(%i)", 1 + (int)std::distance(participants.begin(), std::find_if(participants.begin(), participants.end(), [&](const participant_ref& item) { return item.seed == next->seed; }))));
						break;
					case algorithm::composition::phase::finalized:
						mpc_timeline.push_back("finalize");
						break;
					default:
						VI_PANIC(false, "invalid phase");
						break;
				}
				if (next == mpc_phase_participants.end())
					break;

				format::wo_stream message;
				algorithm::composition::store_compositor(alg, *mpc_state, &message).expect("failed to store the state");

				auto reader = message.ro();
				mpc_state = algorithm::composition::load_compositor(reader).expect("failed to load the state");
				mpc_state->aggregate(next->keypair.secret_key).expect("failed to aggregate the state");
				mpc_phase_participants.erase(next);

				format::wo_stream updated_message;
				algorithm::composition::store_compositor(alg, *mpc_state, &updated_message).expect("failed to store the state");
				mpc_state_bandwidth += message.data.size() + updated_message.data.size();
				mpc_state_time += date_time().nanoseconds() - time.nanoseconds();
				++mpc_steps;
			}

			algorithm::composition::cpubkey_t mpc_public_key;
			algorithm::composition::chashsig_t mpc_signature;
			mpc_state->to_public_key(&mpc_public_key).expect("failed to extract public key from state");
			mpc_state->to_signature(&mpc_signature).expect("failed to extract signature from state");

			auto* aggregation_data = mpc_data.set("aggregation", format::tree::map());
			auto* aggregation_timeline_data = aggregation_data->set("timeline", format::tree::list());
			for (auto& item : mpc_timeline)
				aggregation_timeline_data->push(format::variable(item));
			aggregation_data->set("public_key", format::variable(format::util::encode_0xhex(std::string_view((char*)mpc_public_key.data(), mpc_public_key.size()))));
			aggregation_data->set("signature", format::variable(format::util::encode_0xhex(std::string_view((char*)mpc_signature.data(), mpc_signature.size()))));
			aggregation_data->set("network_bytes_required", format::variable(mpc_state_bandwidth));
			aggregation_data->set("network_communications", format::variable(mpc_steps * 2));
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
		auto* server = superchain::server_node::get();
		auto* term = console::get();
		auto seed = uint256_t(123456);
		auto user = ledger::wallet::from_seed(seed.to_string());
		auto create_wallet = [&](const algorithm::asset_id& asset) -> superchain::computed_wallet
		{
			uint8_t seed_buffer[32];
			seed.encode(seed_buffer);

			auto wallet = *server->compute_wallet(asset, seed_buffer, sizeof(seed_buffer));
			for (auto& encoded_address : wallet.encoded_addresses)
				server->enable_link(asset, superchain::wallet_link(user.public_key_hash, wallet.encoded_public_key, encoded_address.second)).expect("link activation error");
			return wallet;
		};
		auto validate_transaction = [&](const algorithm::asset_id& asset, const superchain::computed_wallet& wallet, superchain::prepared_transaction& prepared, const std::string_view& feature, const std::string_view& expected_calldata)
		{
			for (auto& input : prepared.inputs)
			{
				auto state = algorithm::composition::make_signature_compositor(input.alg, input.public_key, input.message.data(), input.message.size(), 1).expect("state initialization error");
				while (state->next_phase() != algorithm::composition::phase::finalized)
					state->aggregate(wallet.secret_key).expect("signature aggregation error");
				state->to_signature(&input.signature);
			}

			superchain::finalized_transaction finalized = server->finalize_transaction(asset, std::move(prepared)).expect("prepared transaction finalization error");
			VI_PANIC(finalized.calldata == expected_calldata, "resulting calldata differs from expected calldata");
			term->fwrite_line("%s (%.*s) = %s", algorithm::asset::handle_of(asset).c_str(), (int)feature.size(), feature.data(), finalized.calldata.c_str());
		};
		tester::use_clean_state([&]()
		{
			auto asset = algorithm::asset::id_of("BTC");
			auto state = storages::superchainstate(asset);
			auto options = format::tree::list();
			options.push(format::variable("p2pk"));
			options.push(format::variable("p2sh_p2wpkh"));
			options.push(format::variable("p2pkh"));
			options.push(format::variable("p2wsh_p2pkh"));
			options.push(format::variable("p2wpkh"));
			options.push(format::variable("p2tr"));
			server->add_specifications(asset, options);

			auto wallet = create_wallet(asset);
			server->add_specifications(asset, format::tree());

			auto input_p2pkh_hash = codec::hex_decode("0x57e30b41a6d984cdb763145f32ad9678a9b2bfd0267e12d5d0474e97f7d077d0");
			superchain::coin_utxo input_p2pkh;
			input_p2pkh.link = superchain::wallet_link(user.public_key_hash, wallet.encoded_public_key, wallet.encoded_addresses[3]);
			input_p2pkh.transaction_id = "382940bfc9a1fe1f09a3fb8e1fda1b25b90dc2019ff5973b1d9d616e15b29840";
			input_p2pkh.index = 1;
			input_p2pkh.value = 0.1;

			auto input_p2sh_hash = codec::hex_decode("0xc4e23865424498b4d90c57dda4bea4718e1e6ed669cc00796afd864ac6de3606");
			superchain::coin_utxo input_p2sh;
			input_p2sh.link = superchain::wallet_link(user.public_key_hash, wallet.encoded_public_key, wallet.encoded_addresses[2]);
			input_p2sh.transaction_id = "3d7c1f8e03a73821517d2f0220fe3ecf82c2f55b94b724e5d5298c87070802a0";
			input_p2sh.value = 0.1;

			auto input_p2wpkh_hash_1 = codec::hex_decode("0xe79739ac82960be8bedb5175203bd65880b0c45c5c0286d54b5bc6eb4bac3898");
			superchain::coin_utxo input_p2wpkh_1;
			input_p2wpkh_1.link = superchain::wallet_link(user.public_key_hash, wallet.encoded_public_key, wallet.encoded_addresses[6]);
			input_p2wpkh_1.transaction_id = "5594c04289179bff0f434e5349fafbaa4d43da403b9dc7a637f5afe035b99729";
			input_p2wpkh_1.value = 0.1;

			auto input_p2tr_public_key = compositions::secp256k1_point_t(wallet.public_key);
			auto input_p2tr_tweak = compositions::secp256k1_scalar_t(codec::hex_decode("0x04c32a8b5fae170a7a0d28332a663b96f43d24ed4c9db30dfdd9d9d053d3d3e6"));
			auto input_p2tr_tweaked_public_key = compositions::secp256k1_schnorr_compositor::to_tweaked_public_key(input_p2tr_public_key, input_p2tr_tweak).expect("failed to tweak a public key");
			auto input_p2tr_hash = codec::hex_decode("0x50cc324f902032625ba70fdfee889032a7ff4de1c7732dc3982b72c1ba2df8b5");
			superchain::coin_utxo input_p2tr;
			input_p2tr.link = superchain::wallet_link(user.public_key_hash, wallet.encoded_public_key, wallet.encoded_addresses[4]);
			input_p2tr.transaction_id = "988fcb7035c0f51688ddcfaf92ec8fdd0e9bda8b53aa3403bf096611147fb325";
			input_p2tr.value = 0.1;

			auto input_p2wpkh_hash_2 = codec::hex_decode("0x16a41f749d25f7ebae96aabd62207c2189ac3623b2ddee4560213a3563f81042");
			superchain::coin_utxo input_p2wpkh_2;
			input_p2wpkh_2.link = superchain::wallet_link(user.public_key_hash, wallet.encoded_public_key, wallet.encoded_addresses[6]);
			input_p2wpkh_2.transaction_id = "9b7a67a6a46f48f896c1de89d479d9d1f5b284809065671ff931c800e1041530";
			input_p2wpkh_2.value = 0.1;

			auto input_p2wsh_hash = codec::hex_decode("0x40cfd352d152929ada057d28c0e18f781a8b9ddb24df1b6381b0738c8f0ccbb9");
			superchain::coin_utxo input_p2wsh;
			input_p2wsh.link = superchain::wallet_link(user.public_key_hash, wallet.encoded_public_key, wallet.encoded_addresses[5]);
			input_p2wsh.transaction_id = "ccc7949d20241f04362c42e20125c83096a617b906e1d8123d1b8b08740c6025";
			input_p2wsh.index = 1;
			input_p2wsh.value = decimal("0.1001");

			auto input_p2pk_hash = codec::hex_decode("0xe665fd68a288da956f73810db79647a59dbbd6dafb0891f97364a0dfff520b2e");
			superchain::coin_utxo input_p2pk;
			input_p2pk.link = superchain::wallet_link(user.public_key_hash, wallet.encoded_public_key, wallet.encoded_addresses[1]);
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
			validate_transaction(asset, wallet, prepared, "p2pk, p2pkh, p2sh, p2wpkh, p2wsh, p2tr", "010000000001074098b2156e619d1d3b97f59f01c20db9251bda1f8efba3091ffea1c9bf402938010000006a47304402204e33cc4508a8a3b80718856850d6d44c258cd8cb0085471feeee870c0174eedd02201749240ef5961c36956209ab4c4928adfa68555dacefa684383f8f88680897a5012102986445ccfd323143f392b66b8cfc056df90ebdc110573e3395ee670d5043f23affffffffa0020807878c29d5e524b7945bf5c282cf3efe20022f7d512138a7038e1f7c3d000000001716001418e254169de2c06bbe881f971b312084bf7d7e1cffffffff2997b935e0aff537a6c79d3b40da434daafbfa49534e430fff9b178942c094550000000000ffffffff25b37f14116609bf0334aa538bda9b0edd8fec92afcfdd8816f5c03570cb8f980000000000ffffffff301504e100c831f91f6765908084b2f5d1d979d489dec196f8486fa4a6677a9b0000000000ffffffff25600c74088b1b3d12d8e106b917a69630c82501e2422c36041f24209d94c7cc0100000000ffffffff2ff68c1d9ecbbd544e90827282fc60d2080041610338f27d6778d56c38d2b0f00000000049483045022100a91590f6154e6116afa393a4c71cb337b8a9bd1a83dc2305bc5718dcde9c1b45022001a60381a18b6b224c71193817a1d76b78d00334bbd651ec3e17e7fe7673a06401ffffffff0240d2df03000000001600142fe07053c38596c34f561a2565b752272c90e66430244c00000000001976a91418e254169de2c06bbe881f971b312084bf7d7e1c88ac0002483045022100b51bf896785af284690485b6b9fff90ee000032b7c135ec4a3b2cf1ee6ae9b5202203fa9aabd0ea22482e5f955fa0eb8e696d50fe2999793857f13be39ddc1871a89012102986445ccfd323143f392b66b8cfc056df90ebdc110573e3395ee670d5043f23a02483045022100b5ffeb7bb826eb7f743f32e7026d20cba8403a46de21ba3cc92bbcf228e8de6e02202fa447539d338f884ece7c4c181b8b590a846f3f9469721304ed0cbc407ee672012102986445ccfd323143f392b66b8cfc056df90ebdc110573e3395ee670d5043f23a014026371d3a2baaf32f56cc0e8bb0f940d243facb694ee877b34540100c5498a2ef6698effdc811e516e62ba20f187ebdc25e30208b787eac053875292088c09a56024730440220381691df2e8d7c5afdd7f71287351ec3a551a2d7a0b1afdaaa3afe42112ca0c90220408dc12aa8351c3a6808019db1b05afa4ca0798578582c259190cdcf756685b7012102986445ccfd323143f392b66b8cfc056df90ebdc110573e3395ee670d5043f23a03483045022100aefdc4da0db0934e6ba5bcd9b6f624c995c432420e237047be28aa4656eea5c0022054fd1563c3538bbec6132b8d8eb21ea49df81f059d50b1f01f3cb0fc18981715012102986445ccfd323143f392b66b8cfc056df90ebdc110573e3395ee670d5043f23a1976a91418e254169de2c06bbe881f971b312084bf7d7e1c88ac0000000000");
		});
		tester::use_clean_state([&]()
		{
			auto asset = algorithm::asset::id_of("BCH");
			auto state = storages::superchainstate(asset);
			auto wallet = create_wallet(asset);

			auto input_p2pkh_hash = codec::hex_decode("0x06da9b13756115c79c0361a083d340c75ced09ddfec9a530601d73a0021ba6a5");
			superchain::coin_utxo input_p2pkh;
			input_p2pkh.link = superchain::wallet_link(user.public_key_hash, wallet.encoded_public_key, wallet.encoded_addresses[1]);
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
			validate_transaction(asset, wallet, prepared, "p2pkh", "0100000001d45e7ec637177870d7a5ee572810f75d37e5b5fc6718872c392dc510a857418d000000006a47304402207fe230c834aebaa9c865ab75ff1b95efd40b1bce71c53b7f16ba09a6b99b4f0c022057fbc1f185f135ab29da2f701cecb22e53cc93e373edb429ac54a179b1c3e31f412102986445ccfd323143f392b66b8cfc056df90ebdc110573e3395ee670d5043f23affffffff01e00f9700000000001976a9148222fac0608b29696d1e9c66afc225fcc5ecf37188ac00000000");
		});
		tester::use_clean_state([&]()
		{
			auto asset = algorithm::asset::id_of("ETH");
			auto state = storages::superchainstate(asset);
			auto wallet = create_wallet(asset);

			auto signable_link = superchain::wallet_link(user.public_key_hash, wallet.encoded_public_key, wallet.encoded_addresses.begin()->second);
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
			validate_transaction(asset, wallet, prepared, "eip155, transfer", "0xf86d02843b9aca008252089492f9727da59be92f945a72f6ed9b5de8783e09d3872386f26fc100008083016e3ba04f23060887ee716ad705ccde419b669f08ccbc56c14a6ff86fd2e4388226cf81a0136329e2bdd7c7c129109a14e22e5f4e7f3c0a952b12ba2543fe66e745018fa0");

			auto token_asset = algorithm::asset::id_of("ETH", "TT", "0xDcbcBF00604Bad29E53C60ac1151866Fa0CC2920");
			signable_link = superchain::wallet_link(user.public_key_hash, wallet.encoded_public_key, wallet.encoded_addresses.begin()->second);
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
			validate_transaction(asset, wallet, prepared, "eip155, erc20 transfer", "0xf8ab01843b9aca0082c64694dcbcbf00604bad29e53c60ac1151866fa0cc292080b844a9059cbb000000000000000000000000ba119f26a40145b463dfcae2590b68a057e81d3d00000000000000000000000000000000000000000000001b4486fafde57c000083016e3ba0ed04c78bd290e92362d6909eeec76449896155669823ab22de90946298b0c7d0a03848a83fd7176228568a3ee5420ff000e835c8545c3df103585e1fe432c8add5");

			signable_link = superchain::wallet_link(user.public_key_hash, wallet.encoded_public_key, wallet.encoded_addresses.begin()->second);
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
			validate_transaction(asset, wallet, prepared, "eip1559, transfer", "0x02f87482b70c02843b9ac618843b9aca008252089492f9727da59be92f945a72f6ed9b5de8783e09d388016345785d8a000080c080a0eda871a82df5e49f511ab477dced74ceca92f8ca029446806532d4c63ac22a0ea07cf12c3653e13eb49979ed1c8bb84237bcf8b292e8b9a67733cb8885565d15dd");

			signable_link = superchain::wallet_link(user.public_key_hash, wallet.encoded_public_key, wallet.encoded_addresses.begin()->second);
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
			validate_transaction(asset, wallet, prepared, "eip1559, erc20 transfer", "0x02f8b182b70c02843b9ac618843b9aca0082c64694dcbcbf00604bad29e53c60ac1151866fa0cc292080b844a9059cbb000000000000000000000000ba119f26a40145b463dfcae2590b68a057e81d3d00000000000000000000000000000000000000000000001b4486fafde57c0000c080a08b7e707643445feff0d8b6cd6ef4b2419df4609d7980272ef54f84b77db9ae04a02a895ed9e13c31e400e30dc11371a2e2a2ff0817ce99110593bd6c4b39ae393f");
		});
		tester::use_clean_state([&]()
		{
			auto asset = algorithm::asset::id_of("XRP");
			auto state = storages::superchainstate(asset);
			auto wallet = create_wallet(asset);

			auto signable_link = superchain::wallet_link(user.public_key_hash, wallet.encoded_public_key, wallet.encoded_addresses.begin()->second);
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

			auto signable_link = superchain::wallet_link(user.public_key_hash, wallet.encoded_public_key, wallet.encoded_addresses.begin()->second);
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

			signable_link = superchain::wallet_link(user.public_key_hash, wallet.encoded_public_key, wallet.encoded_addresses.begin()->second);
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

			auto signable_link = superchain::wallet_link(user.public_key_hash, wallet.encoded_public_key, wallet.encoded_addresses.begin()->second);
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
			signable_link = superchain::wallet_link(user.public_key_hash, wallet.encoded_public_key, wallet.encoded_addresses.begin()->second);
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
		});
		tester::use_clean_state([&]()
		{
			auto asset = algorithm::asset::id_of("ADA");
			auto state = storages::superchainstate(asset);
			auto wallet = create_wallet(asset);

			auto input_hash = codec::hex_decode("0x14b33fbdd10c0931057b2c66e56b08cf01523480769153e3433050c571dc23e6");
			superchain::coin_utxo input;
			input.link = superchain::wallet_link(user.public_key_hash, wallet.encoded_public_key, wallet.encoded_addresses[1]);
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
			input.link = superchain::wallet_link(user.public_key_hash, wallet.encoded_public_key, wallet.encoded_addresses[1]);
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

			auto signable_link = superchain::wallet_link(user.public_key_hash, wallet.encoded_public_key, wallet.encoded_addresses.begin()->second);
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
			validate_transaction(asset, wallet, prepared, "transfer", "78da8d52cb6edc300cfc179d839494443df6da5e7aef2d080c4aa212a3def5c2f6e68120ff5eba6983b4bdd4be48c3d70c352fe6615cc7328939749e56b932dbd3d72fe6604275c02537b42c3e55aa210190739e50ba056cb52688398130a6e8b203e4aa89b635e9ae8ab9320b3f0e8d371eeee5493b0283858c6c2da4e47de14cb1046484543c14489872aae29c25d66109106df0c0b6451f73844056420c5dff186aa0808ae5e814758a35db23441b7af47adb916a85bc221824ba100245eb775ce21beaa247eb542692c7aa5a6a537abd6590aa3d6ac68cd89a8f52a4510b25844c68f76ce142d0152a410972d03912894a256c29d7a2d99843f2981214cd8310a101d7446f0a33002660579d8f1f36650e2fa6cea76de1ba99c3cd8b39f3c247d964d9230f3c5d643f6cf3c0ad2db2aebad6ff27a383e6c7932c7f14ffaf6e2de6e37c39292ff4f0f37b55b33c9f65b82c93b6da8fd777f37c37099fc7f5bacec74fe765dee63a4fd7df163ead5d96cfbfc5fdaad5ba7f43b7ba10e94399e6fa7d28cf9bec4c77e7988f817b5eef15ffdb499a234fe771e16d9c4fca357a4fea4f6f95b0ce1c8fb26e7c3cbf476c7a8b7491611a8fe3ae8fe05de03ade9d78bb2ccaf4c66885ee878bad1d2526921ec9aaf5d54fb46f4d1fb8e7c41ca920546f111abbd2a5abe1256081c8a84fd4212475b125ef441b052a6a714aaa02599a5517b3f35a9bc079c6dc804ab660316035b7af3f00d54e1100");

			auto token_asset = algorithm::asset::id_of("TRX", "GFC", "TUiyUe3uqtiT8cFkfhW6Q28Z99sY7o82Xr");
			signable_link = superchain::wallet_link(user.public_key_hash, wallet.encoded_public_key, wallet.encoded_addresses.begin()->second);
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
			validate_transaction(asset, wallet, prepared, "trc20 transfer", "78dacd54cb6edc300cfc179d839494443df6da5e7a6e6f41b0a0246a63d41b2f6ce78520ff5eba498ab46881a0a7ca80210d4969c811f5686e876528a3985de7719133b3de7ffe6476a64384c2e202b990a3ab54d9660a31a4946cb325a3f752a3afbdfb105defd5632a492dd03817306766e6bb7de395f75772af3b028385a4dbe83fb746c175292939a62c1e0ab0744e459cb3c42c8090b0a3e5ac3376187dcc110259510e5dbf186aa0808a293d459d62cdf608d1861ebdae36a45a21af4856ff18285a4da769948dde6f76899b15838b1e150346f258634eb565e4de3248d5bd6ac68cd89a8f52a4510b25844c687f78b7927d686cd14af745b1e874915ae0445d7cea2e587062adf79a0de55a0afc65081782aedb97006c3928778944a512b6a4817a32e6903cfcf3888c56ffd0a0e51e9eeb9d01306991abf3f18d6e66f768ea74bdce5c57b3bb7834279ef928abcc9be596c71bd926cfaee67f494d1398eeae65de736bb32c8b527bbfa21afc9af1aff1efd4d83c69033d9c647f338f1ab84dcf0fd37418854fc3725ea7e387d33cad539dc6f3aff37038c8fce5c8f3faf1b5cc2ff11afb67f3a5ca237d5fc6a97edb978755367e5b5799b7862b5eae14ffbdcbd447ee4fc3cceb305d9b9df694a71451db1240cf1d8eb2ac7c3cfdb4807fb67491fd381c07bd05482fc556a2cb70b8e6f56656b6170639559f2884ae97c8a1a3ec902c10875c7c8eb9828bda9cbdd9448412547795443bd8368a5a53efb43992af2aa1a4843166a8caba49f0bd17d758a4e96b8054c1930ae00bb9e4f41db2c96149018bb97cfa0e466052a6");
		});
	}
	/* blockchain containing all transaction types (zero balance accounts, valid regtest chain) */
	static void blockchain_full_coverage(vector<account_ref>* userdata)
	{
		tester::use_clean_state([&]()
		{
			vector<account_ref> users; vector<algorithm::pubkeyhash_t> contracts;
			for (size_t i = 0; i < protocol::now().policy.participation.min_per_account + 1; i++)
				users.push_back(account_ref(ledger::wallet::from_seed(stringify::text("00000%i", (int)i)), 0));

			format::tree results;
			format::tree* data = userdata ? nullptr : &results;
			TEST_BLOCK(&generators::setup_stage_1, "0xd61bee59131178ed1dd83feebb0440a4b68cfa5b26dab744b69cc3804bc00c77", 1);
			TEST_BLOCK(std::bind(&generators::setup_custom, std::placeholders::_1, std::placeholders::_2, 2, 1, 0), "0xeab031314d8ee5164709ef28cea868770de9afafd7918098fed9ea3eeab962eb", 2);
			TEST_BLOCK(&generators::route_stage_1, "0x804b9f9abe260985f98974d7a6ea2ac322bc8b38e7f3d3860b235e9a49fd6e9b", 3);
			TEST_BLOCK(&generators::route_stage_2, "0xbdb831226025a00fc996a19a38184f11dd34a2a9e0ab13d6ca169017babd9ff3", 5);
			TEST_BLOCK(&generators::attestate_stage_1, "0xf0b59cdff062650fbf4d85200ca7f5253d48546dac44eb101b1379fda4b6dcfa", 7);
			TEST_BLOCK(&generators::transfer_stage_1, "0xbd08402823d785a3bc2298571908b2d4bf3f1676b94f1d99913c56b6a526f0f9", 8);
			TEST_BLOCK(&generators::transfer_stage_2, "0x46c842ed965a912190963652907b3f1e29bc2c545ddd03ce0289593b954837da", 9);
			TEST_BLOCK(std::bind(&generators::transfer_custom, std::placeholders::_1, std::placeholders::_2, 0, algorithm::asset::id_of("BTC"), users[2].wallet.get_address(), 0.05), "0x2aa08a037b661997bf08421368db08167af86b16566555e777c49dfb321e0660", 10);
			TEST_BLOCK(std::bind(&generators::deploy_stage_1, std::placeholders::_1, std::placeholders::_2, &contracts), "0x61770575e00a486f19941ae7310ecbbcbb75016a2702625a935a9cb7afff6527", 11);
			TEST_BLOCK(std::bind(&generators::deploy_stage_2, std::placeholders::_1, std::placeholders::_2, &contracts), "0xc3fd837fe56cf3b984a2632c852301dcfbd72d3bc80de7d89527a3246ef1250c", 12);
			TEST_BLOCK(std::bind(&generators::call_stage_1, std::placeholders::_1, std::placeholders::_2, &contracts), "0xad3c9f721828dd250de14bc56362751287ee5b904b0d16a494f15f91abcd47c7", 13);
			TEST_BLOCK(&generators::rollup_stage_1, "0x6fcb1e4f315eea7c949bdd4635b38b491ce6ac286c34c4bb2771827855dd52aa", 14);
			TEST_BLOCK(std::bind(&generators::setup_custom, std::placeholders::_1, std::placeholders::_2, 2, 0, 1), "0x509f194091055552007767ce2a8a9cd351a354b9d79424482996e92fe4cd5ade", 15);
			TEST_BLOCK_FAULT(&generators::migrate_stage_1, "0x3cc7992bbfbc5e0351aac3fa8e50273a488a8c5a727d2ac120e97b0c5bba74b4", 16);
			TEST_BLOCK(&generators::migrate_stage_2, "0xcac5091491272c8c9312a33822c38321bc06efe981d941609e2bdc0e5c859e40", 18);
			TEST_BLOCK(&generators::migrate_stage_3, "0xb66ee618eca5d3483e496de3693ae69cbdc7bc842965ca112a315ee2ae613778", 20);
			TEST_BLOCK(&generators::withdraw_stage_1, "0x99b8c75d7a52304b16780ada4db2ada245909229ca5c448f8346a01fded3d7c8", 22);
			TEST_BLOCK(&generators::withdraw_stage_2, "0x2ae071d641105cc5596b26095f970dec1be8fa5253db2b859a16c6ba8ffa6eb3", 24);
			TEST_BLOCK(&generators::withdraw_stage_3, "0xe85b72ffe41932210323bd728aa94312ca66bc5a19dbfcc70be603b7c917a121", 26);
			TEST_BLOCK(&generators::withdraw_stage_4, "0x5a23b8383663a93fa566e626d6bce0d4cca9191b44cfc27a18d4ed6d8761db72", 27);
			TEST_BLOCK(&generators::withdraw_stage_5, "0xcb940983a01b5967bb2295885b8cda65be1f54dd4fc0d2c508def269f1cee8a4", 29);
			TEST_BLOCK(&generators::withdraw_stage_6, "0xe712e917e05786e3988ce78e6081ac008ee42f4c252f7c912b18210767462700", 31);
			TEST_BLOCK(std::bind(&generators::setup_custom, std::placeholders::_1, std::placeholders::_2, 2, 1, 0), "0xc9dd7fa1184913abf35570a5703ca1163f503225ba81951c493bc639853699b3", 33);
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
			for (size_t i = 0; i < protocol::now().policy.participation.min_per_account; i++)
				users.push_back(account_ref(ledger::wallet::from_seed(stringify::text("00000%i", (int)i)), 0));

			format::tree results;
			format::tree* data = userdata ? nullptr : &results;
			TEST_BLOCK(&generators::setup_stage_0, "0x8dddbd714522677ec180556288040420882fce72f174c5001ada57296b6b25ee", 1);
			TEST_BLOCK(&generators::route_stage_0, "0x66b5ab5fb69446f4879964fd7e0f43cc6b1255ba7d5d6ca8359d6e99ef4471dc", 2);
			TEST_BLOCK(&generators::attestate_stage_0, "0x3a2b7a5649dd834659a97b5ef255fb0e50c6bc5c44f4a553212efc2d64f5c4de", 4);
			TEST_BLOCK(std::bind(&generators::transfer_custom, std::placeholders::_1, std::placeholders::_2, 0, algorithm::asset::id_of("BTC"), "tcrt1x00g22stp0qcprrxra7x2pz2au33armtfc50460", 5), "0xed0f6b5827302cb60583bf1830c80a165884e56f56fe5f520915d0e4a5be427c", 5);
			TEST_BLOCK(std::bind(&generators::transfer_custom, std::placeholders::_1, std::placeholders::_2, 0, algorithm::asset::id_of("ETH", "tBTC", "0x18084fbA666a33d37592fA2633fD49a74DD93a88"), "tcrt1x00g22stp0qcprrxra7x2pz2au33armtfc50460", 5), "0x88b7d2fe1f620961e547efa89b4d98ed8ed093b16d99c3d49e735c3f7730daf8", 6);
			TEST_BLOCK(std::bind(&generators::transfer_custom, std::placeholders::_1, std::placeholders::_2, 0, algorithm::asset::id_of("ETH", "USDT", "0xdAC17F958D2ee523a2206206994597C13D831ec7"), "tcrt1x00g22stp0qcprrxra7x2pz2au33armtfc50460", 300000), "0xd6e83599ce05a430c9dd7e31555602a71f1f57e792d4c9347fe5d58c70c5c610", 7);
			TEST_BLOCK(std::bind(&generators::transfer_custom, std::placeholders::_1, std::placeholders::_2, 0, algorithm::asset::id_of("TRX", "USDT", "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"), "tcrt1x00g22stp0qcprrxra7x2pz2au33armtfc50460", 200000), "0xb80556b6d18c1a9840f99d4786b22a5eb0bfcbe5ac9db3d8ea3f6ad5c93b2552", 8);
			TEST_BLOCK(std::bind(&generators::transfer_custom, std::placeholders::_1, std::placeholders::_2, 0, algorithm::asset::id_of("BTC"), "tcrt1xu0k7jd2hsv2x5h80tcslpk3n0kvzzw5kup6vng", 5), "0xb370d2e64a6a2979bd4a34117c617f59f360b2c1d94ef9191af951bee3fef224", 9);
			TEST_BLOCK(std::bind(&generators::transfer_custom, std::placeholders::_1, std::placeholders::_2, 0, algorithm::asset::id_of("ETH", "tBTC", "0x18084fbA666a33d37592fA2633fD49a74DD93a88"), "tcrt1xu0k7jd2hsv2x5h80tcslpk3n0kvzzw5kup6vng", 5), "0xb73f2fbef8df8fdfcce37d40cf162434daf1e420efb252cd4f738ed6e13fb74f", 10);
			TEST_BLOCK(std::bind(&generators::transfer_custom, std::placeholders::_1, std::placeholders::_2, 0, algorithm::asset::id_of("ETH", "USDT", "0xdAC17F958D2ee523a2206206994597C13D831ec7"), "tcrt1xu0k7jd2hsv2x5h80tcslpk3n0kvzzw5kup6vng", 300000), "0x52bd740c518443a5c1ce81017f73a25e6f7cbdd5af3aac53dd81225e232fcc7e", 11);
			TEST_BLOCK(std::bind(&generators::transfer_custom, std::placeholders::_1, std::placeholders::_2, 0, algorithm::asset::id_of("TRX", "USDT", "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"), "tcrt1xu0k7jd2hsv2x5h80tcslpk3n0kvzzw5kup6vng", 200000), "0x30d175cb87eddff534ef8bb38906dfee6cb3fa876437037fa4d01b8eb3b8e206", 12);
			if (userdata != nullptr)
				*userdata = std::move(users);
			else
				console::get()->write_line(data->as_json(true));
		});
	}
	/* blockchain exclusively for testing bridges of specific networks (possibly non-zero balance accounts, valid regtest chain) */
	static void blockchain_integration_coverage(const algorithm::asset_id& asset, const hash_map<string, string>& urls, uint64_t block_number, const decimal& deposit_value, const decimal& bridge_fee, std::function<string()>&& new_account, std::function<void(const std::string_view&, bool)>&& new_block, std::function<void(const std::string_view&, const std::string_view&, const decimal&)>&& new_transaction)
	{
		tester::use_clean_state([&]()
		{
			vector<account_ref> producers;
			for (size_t i = 0; i < protocol::now().policy.participation.min_per_account; i++)
				producers.push_back(account_ref(ledger::wallet::from_seed(stringify::text("00000%i", (int)i)), 0));

			auto* term = console::get();
			auto& [user1, user1_nonce] = producers[0];
			auto& [user2, user2_nonce] = producers[1];
			auto [user3, user3_nonce] = account_ref(ledger::wallet::from_seed("000003"), 0);
			auto* setup = memory::init<transactions::setup>();
			setup->asset = asset;
			setup->allocate_production_stake(decimal::zero());
			setup->allocate_attestation_stake(asset, decimal::zero());
			setup->configure_attestation_security(asset, protocol::now().policy.participation.min_per_account, decimal::zero(), true, true);
			setup->allocate_participation_stake(decimal::zero());
			setup->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
			tester::new_block_from_one(nullptr, producers, setup);

			for (size_t i = 1; i < producers.size(); i++)
			{
				auto& [user, user_nonce] = producers[i];
				setup = memory::init<transactions::setup>();
				setup->asset = asset;
				setup->allocate_attestation_stake(asset, decimal::zero());
				setup->allocate_participation_stake(decimal::zero());
				setup->sign(user.secret_key, user_nonce++, decimal::zero()).expect("pre-validation failed");
				tester::new_block_from_one(nullptr, producers, setup);
			}

			auto* bridge_account = memory::init<transactions::route>();
			bridge_account->asset = asset;
			bridge_account->set_manager(user1.public_key_hash);
			bridge_account->sign(user1.secret_key, user1_nonce++, decimal::zero()).expect("pre-validation failed");
			tester::new_block_from_one(nullptr, producers, bridge_account);

			auto& config = protocol::change();
			config.user.superchain.server = true;

			auto* server = superchain::server_node::get();
			auto params = (superchain::relay_backend::chainparams*)server->get_chainparams(asset);
			auto& options = server->get_options();
			params->sync_latency = 0;
			options.polling_frequency = 3000;

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
			server->add_multi_node(asset, hash_map<string, string>(urls), 0);
			server->add_transaction_callback("logging", [&](const algorithm::asset_id& asset, const superchain::chain_supervisor_options& options, superchain::transaction_logs&& logs) -> expects_lr<void>
			{
				auto transactions = vector<uptr<ledger::transaction>>();
				for (auto& receipt : logs.receipts)
				{
					auto* transaction = memory::init<transactions::attestate>();
					transaction->asset = asset;
					transaction->set_computed_proof(std::move(receipt), { });
					transactions.push_back(transaction);
				}

				bool log_acquired = !transactions.empty();
				if (log_acquired)
					tester::new_block_from_list(nullptr, producers, std::move(transactions));

				std::unique_lock<std::mutex> unique(mutex);
				transaction_status = log_acquired ? 1 : (transaction_status.load() <= 0 ? -1 : 1);
				condition.notify_one();
				return expectation::met;
			});
			server->scan_from_block_height(asset, block_number);
			term->write_line("incoming transaction integration:");
			term->fwrite_line(" - account required");

			auto from_account = new_account();
			bridge_account = memory::init<transactions::route>();
			bridge_account->asset = asset;
			bridge_account->set_routing_address(from_account);
			bridge_account->set_manager(user1.public_key_hash);
			bridge_account->sign(user3.secret_key, user3_nonce++, decimal::zero()).expect("pre-validation failed");
			tester::new_block_from_one(nullptr, producers, bridge_account);

			size_t deposits = 0;
			auto executor = ledger::executor_context(nullptr);
			auto accounts = *executor.get_witness_accounts_by_purpose(params->routing == superchain::routing_policy::account ? user1.public_key_hash : user3.public_key_hash, states::witness_account::account_type::bridge, 0, 128);
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

			auto expected_balance = (deposit_value - bridge_fee) * deposits;
			auto balance = executor.get_account_balance(asset, user3.public_key_hash).expect("balance mismatch").get_balance();
			auto withdrawal_value = balance - bridge_fee;
			VI_PANIC(balance == expected_balance, "actual balance is expected to be %s but is %s", expected_balance.to_string().c_str(), balance.to_string().c_str());
			term->write_line("outgoing transaction integration:");
			term->fwrite_line(" - withdraw %s into %.*s", withdrawal_value.to_string().c_str(), (int)from_account.size(), from_account.data());

			auto* withdraw = memory::init<transactions::withdraw>();
			withdraw->asset = asset;
			withdraw->set_manager(user1.public_key_hash);
			withdraw->set_to(from_account, withdrawal_value);
			withdraw->sign(user3.secret_key, user3_nonce++, decimal::zero()).expect("pre-validation failed");
			tester::new_block_from_one(nullptr, producers, withdraw);

			auto chain = storages::chainstate();
			auto confirmation_block = chain.get_latest_block();
			VI_PANIC(confirmation_block && !confirmation_block->transactions.empty(), "blocks with withdrawal confirmation were not found");

			auto& confirmation = confirmation_block->transactions.front();
			VI_PANIC(confirmation.transaction->as_type() == transactions::broadcast::as_instance_type(), "no withdrawal confirmation");

			auto* confirmation_event = confirmation.receipt.find_event<transactions::broadcast>();
			auto* confirmation_transaction = (transactions::broadcast*)*confirmation.transaction;
			VI_PANIC(confirmation_transaction->proof && !confirmation_event, "withdrawal confirmation failed: %s", confirmation_event ? (confirmation_event->empty() ? "unknown error" : confirmation_event->front().as_blob().c_str()) : confirmation_transaction->proof.what().c_str());
			term->fwrite_line(" - block required for transaction %s", confirmation_transaction->proof->hashdata.c_str());
			new_block(from_account, true);
			receive_transaction();

			balance = executor.get_account_balance(asset, user3.public_key_hash).or_else(states::account_balance(user3.public_key_hash, asset, nullptr)).get_balance();
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
		format::tree data = format::tree::list();
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
			auto validation = next->validate(parent_block.address(), &evaluation);
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
			for (auto& [index, change] : evaluation.state.finalized)
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
		transaction.allocate_attestation_stake(algorithm::asset::id_of("ETH"), decimal::zero());
		transaction.allocate_attestation_stake(algorithm::asset::id_of("XRP"), decimal::zero());
		transaction.allocate_attestation_stake(algorithm::asset::id_of("BTC"), decimal::zero());
		transaction.allocate_participation_stake(decimal::zero());
		VI_PANIC(transaction.sign(from, 1, decimal::zero()), "setup not signed");

		format::tree data = format::tree::map();
		data.set("setup_transaction_gas_limit", algorithm::encoding::serialize_uint256(transaction.gas_limit));
		data.set("block_commitment_limit", algorithm::encoding::serialize_uint256(ledger::block::get_commitment_limit()));
		data.set("block_transaction_limit", algorithm::encoding::serialize_uint256(ledger::block::get_transaction_limit()));
		data.set("block_commitment_gas_limit", algorithm::encoding::serialize_uint256(ledger::block::get_commitment_gas_limit()));
		data.set("block_transaction_gas_limit", algorithm::encoding::serialize_uint256(ledger::block::get_transaction_gas_limit()));
		data.set("block_total_gas_limit", algorithm::encoding::serialize_uint256(ledger::block::get_total_gas_limit()));
		term->write_line(data.as_json(true));
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
	{
		/* consensus, discovery, superchain, rpc nodes */
		auto test_account = from_string<uint32_t>(args.get("test-account"));
		if (test_account)
		{
			ledger::wallet wallet = ledger::wallet::from_seed(stringify::text("00000%i", *test_account - 1));
			ledger::node node;
			node.address = socket_address(params.user.consensus.address, params.user.consensus.port);
			node.version = protocol::now().message.protocol_version;
			storages::mempoolstate().apply_runner_node(std::make_pair(node, wallet));
			console::get()->write_line(wallet.as_tree().as_json(true));
		}

		consensus::server_node consensus_service;
		discovery::server_node discovery_service;
		superchain::server_node& superchain_service = *superchain::server_node::get();
		rpc::server_node rpc_service = rpc::server_node(&consensus_service);

		service_control control;
		control.bind(discovery_service.get_entrypoint());
		control.bind(consensus_service.get_entrypoint());
		control.bind(superchain_service.get_entrypoint());
		control.bind(rpc_service.get_entrypoint());
		exit_code = control.launch();
	}
	else if (test == "benchmark")
	{
		/* blockchain derived from partial coverage test with 1920 additional blocks filled with configurable entropy transactions (non-zero balance accounts, valid regtest chain, entropy 0 - low entropy, entropy 1 - medium entropy, entropy 2 - high entropy) */
		auto* queue = schedule::get();
		queue->start(schedule::desc());

		const size_t block_count = 1000;
		const uint256_t transaction_gas_limit = (size_t)ledger::block::get_transaction_gas_limit();
		const decimal starting_account_balance = decimal(500).truncate(12);
		auto checkpoint = [&](vector<uptr<ledger::transaction>>&& transactions, vector<account_ref>& users)
		{
			static uint64_t cumulative_transaction_count = 0, cumulative_transition_count = 0;
			auto cumulative_query_count = (uint64_t)ledger::storage_util::get_thread_invocations(); term->capture_time();
			auto block = tester::new_block_from_list(nullptr, users, std::move(transactions));
			auto time = term->get_captured_time();
			cumulative_transaction_count += block.transaction_count;
			cumulative_transition_count += block.transition_count;
			term->fwrite_line("%05" PRIu64 ": %s = (d: %s / %.2f ms, t: %" PRIu64 " / %.2f hz, s: %" PRIu64 " / %.2f hz, q: %" PRIu64 " / %.2f hz)",
				block.number, algorithm::encoding::encode_0xhex256(block.as_hash()).c_str(),
				algorithm::wesolowski::kdifficulty(block.difficulty).to_string().c_str(), time,
				cumulative_transaction_count, 1000.0 * (double)block.transaction_count / time,
				cumulative_transition_count, 1000.0 * (double)block.transition_count / time,
				cumulative_query_count, 1000.0 * (double)((uint64_t)ledger::storage_util::get_thread_invocations() - cumulative_query_count) / time);
		};

		vector<account_ref> users;
		tests::blockchain_partial_coverage(&users);

		auto& [user1, user1_nonce] = users[0];
		auto chain = storages::chainstate();
		auto mempool = storages::mempoolstate();
		auto executor = ledger::executor_context(nullptr);
		auto user1_addresses = *executor.get_witness_accounts_by_purpose(user1.public_key_hash, states::witness_account::account_type::bridge, 0, 128);
		auto user1_bridge_address = std::find_if(user1_addresses.begin(), user1_addresses.end(), [](states::witness_account& item) { return item.asset == algorithm::asset::id_of("BTC"); });
		VI_PANIC(user1_bridge_address != user1_addresses.end(), "user 1 bridge address not found");

		auto gas_wallet = ledger::wallet::from_seed();
		transactions::transfer gas_transaction;
		gas_transaction.set_asset("BTC");
		gas_transaction.set_to(gas_wallet.public_key_hash, 0.1);
		gas_transaction.sign(user1.secret_key, user1_nonce, decimal::zero()).expect("pre-validation failed");
		gas_transaction.gas_limit *= 2;

		size_t transaction_count = (size_t)(transaction_gas_limit / gas_transaction.gas_limit);
		transaction_count = std::min(transaction_count, transaction_count - 10);

		auto entropy = from_string<uint8_t>(args.get("test-entropy")).expect("must provide a \"test-entropy\" flag (number in [1, 2, 3])");
		if (entropy == 1)
		{
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

			auto genesis = vector<uptr<ledger::transaction>>();
			genesis.push_back(attestation);
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
			auto* attestation = memory::init<transactions::attestate>();
			attestation->set_asset("BTC");
			attestation->set_finalized_proof(883669,
				"222fc360affb804ad2c34bba2269b36a64a86f017d05a9a60b237e8587bfc52b",
				{ superchain::value_transfer(attestation->asset, "mmtubFoJvXrBuBUQFf1RrowXUbsiPDYnYS", decimal(incoming_quantity)) },
				{ superchain::value_transfer(attestation->asset, user1_bridge_address->addresses.begin()->second, decimal(incoming_quantity)) });
			VI_PANIC(attestation->add_commitment(user1.secret_key), "attestation failed");
			attestation->sign(user1.secret_key, 0, decimal::zero()).expect("pre-validation failed");

			auto genesis = vector<uptr<ledger::transaction>>();
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
			auto* attestation = memory::init<transactions::attestate>();
			attestation->set_asset("BTC");
			attestation->set_finalized_proof(883669,
				"222fc360affb804ad2c34bba2269b36a64a86f017d05a9a60b237e8587bfc52b",
				{ superchain::value_transfer(attestation->asset, "mmtubFoJvXrBuBUQFf1RrowXUbsiPDYnYS", decimal(incoming_quantity)) },
				{ superchain::value_transfer(attestation->asset, user1_bridge_address->addresses.begin()->second, decimal(incoming_quantity)) });
			VI_PANIC(attestation->add_commitment(user1.secret_key), "attestation failed");
			attestation->sign(user1.secret_key, 0, decimal::zero()).expect("pre-validation failed");

			auto genesis = vector<uptr<ledger::transaction>>();
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
		exit_code = 0;
	}
	else if (test == "regression")
	{
		/* test case runner for regression testing */
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
			{ "blockchain / full coverage", std::bind(&tests::blockchain_full_coverage, (vector<account_ref>*)nullptr) },
			{ "blockchain / verification", &tests::blockchain_verification },
			{ "blockchain / partial coverage", std::bind(&tests::blockchain_partial_coverage, (vector<account_ref>*)nullptr) },
			{ "blockchain / verification", &tests::blockchain_verification },
			{ "blockchain / gas estimation", &tests::blockchain_gas_estimation },
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
		exit_code = 0;
	}
	else if (test == "integration")
	{
		/* test case runner for superchain testing */
		auto* queue = schedule::get();
		queue->start(schedule::desc());

		auto path = os::path::resolve(args.get("test-file"), *os::directory::get_working(), true).expect("must provide a \"test-file\" with command list");
		auto list = format::tree::from_json(*os::file::read_as_string(path));
		auto execute = [&](const std::string_view& url, format::tree* requests, const std::string_view& path, std::function<void(string&)>&& replacer) -> string
		{
			if (requests->childs().empty())
				return string();

			format::tree request = requests->childs().size() > 1 ? format::tree::list() : format::tree::map();
			if (requests->childs().size() > 1)
			{
				size_t id = 0;
				for (auto& subrequest : requests->childs())
				{
					auto* data = request.push(format::tree::map());
					data->set("jsonrpc", format::variable("2.0"));
					data->set("method", format::variable(subrequest.key));
					data->set("params", subrequest);
					data->set("id", format::variable(id++));
				}
			}
			else
			{
				auto& subrequest = requests->childs().front();
				request.set("jsonrpc", format::variable("2.0"));
				request.set("method", format::variable(subrequest.key));
				request.set("params", subrequest);
				request.set("id", format::variable((uint8_t)1));
			}

			auto escaped_request_content = request.as_json();
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
		for (auto& node : list->childs())
		{
			auto& blockchain = node.key;
			if (blockchain.empty() || blockchain.front() == '#')
				continue;

			auto deposit_value = node.child_var("deposit_value").as_decimal();
			auto bridge_fee = node.child_var("bridge_fee").as_decimal();
			if (!deposit_value.is_positive())
				deposit_value = 50;
			if (!bridge_fee.is_positive())
				bridge_fee = 0.5;

			hash_map<string, string> urls;
			auto url_bindings = node.child("url");
			if (url_bindings != nullptr && !url_bindings->value.is_string())
			{
				for (auto& protocol : url_bindings->childs())
					urls[protocol.key] = protocol.value.as_blob();
			}
			else if (url_bindings != nullptr)
				urls["auto"] = url_bindings->value.as_blob();

			auto auto_url = urls.find("auto"), jrpc_url = urls.find("jrpc");
			auto url = auto_url == urls.end() ? (jrpc_url == urls.end() ? string() : jrpc_url->second) : auto_url->second;
			auto block_number = node.has("block_number") ? node.child_var("block_number").as_uint64() : 1;
			tests::blockchain_integration_coverage(algorithm::asset::id_of(blockchain), urls, block_number, deposit_value, bridge_fee, [&]()
			{
				auto* account = node.child("account");
				if (!account || !account->value.is_string())
					return execute(url, (format::tree*)node.child("account.0"), node.child_var("account.1").as_blob(), nullptr);

				return account->value.as_blob();
			}, [&](const std::string_view& from_account, bool confirmation)
			{
				auto* reward_block = node.child("block");
				auto* confirmation_block = node.child("confirmation_block");
				auto* block = confirmation ? (confirmation_block ? confirmation_block : reward_block) : reward_block;
				if (!block || !block->value.is_string() || block->value.as_blob() != "#prompt")
				{
					execute(url, (format::tree*)block, std::string_view(), [&](string& content)
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
				auto* transaction = node.child("transaction");
				auto eth_chain = superchain::server_node::get()->get_chain(algorithm::asset::id_of("ETH"));
				auto eth_value = "0x" + eth_chain->to_baseline_value(value).to_string(16);
				if (!transaction || !transaction->value.is_string() || transaction->value.as_blob() != "#prompt")
				{
					execute(url, (format::tree*)transaction, std::string_view(), [&](string& content)
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