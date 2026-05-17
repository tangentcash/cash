#include "delegations.h"
#include "transactions.h"
#define method_bind(h, t, f) while ((h) == method_hash<t, f>(#f)) return method_ptr<t, f>()
#define method_call(p, t, f) (yield_to_delegate((p), method_hash<t, f>(#f)))

namespace tangent
{
	namespace delegations
	{
		typedef void(*gmp_free_t)(void*, size_t);
		static gmp_free_t gmp_free = nullptr;
		template <typename t, expects_lr<void>(t::* target)()>
		static uint32_t method_hash(const std::string_view& signature)
		{
			return algorithm::hashing::hash32d(signature);
		}
		template <typename t, expects_lr<void>(t::* method)()>
		static ledger::delegation_contract::delegate_ptr method_ptr()
		{
			return [](ledger::delegation_contract* base) -> expects_lr<void> { return ((static_cast<t*>(base))->*method)(); };
		}
		static bool must_complete_encrypted_shares(const btree_map<algorithm::pubkey_t, btree_map<algorithm::pubkeyhash_t, string>>& encrypted_shares, const ledger::wallet* runner, size_t group_size)
		{
			int64_t incomplete_encrypted_shares = (int64_t)group_size;
			for (auto& [localized_participant, localized_encrypted_shares] : encrypted_shares)
			{
				if (localized_participant != runner->public_key)
				{
					for (auto& [participant, encrypted_share] : localized_encrypted_shares)
						incomplete_encrypted_shares -= participant == runner->public_key_hash ? 1 : 0;
				}
			}
			return incomplete_encrypted_shares > 0;
		}

		bind_delegation::bind_delegation(ledger::delegation_adapter* new_adapter, const ledger::executor_context* new_executor, const algorithm::pubkeyhash_t& new_runner) : ledger::delegation_contract(new_adapter, new_executor, new_runner)
		{
		}
		bind_delegation::bind_delegation(const bind_delegation& other) : ledger::delegation_contract(other.adapter, other.executor, other.runner->public_key_hash), encrypted_shares(other.encrypted_shares), key_contributions(other.key_contributions), key_commitment(other.key_commitment), attempt(other.attempt)
		{
			if (other.compositor)
				compositor = algorithm::composition::make_compositor_from_copy(*other.compositor).or_else(nullptr);
		}
		expects_promise_rt<void> bind_delegation::execute_transition()
		{
			auto* route = (transactions::route*)executor->transaction;
			auto attester = route->get_attester(executor->receipt);
			if (attester.empty() || !try_running_on(attester))
				return expects_promise_rt<void>(expectation::met);
			else if (executor->get_witness_event(executor->receipt.transaction_hash))
				return expects_promise_rt<void>(expectation::met);

			return coasync<expects_rt<void>>([this, route]() -> expects_promise_rt<void>
			{
				auto group = route->get_participants(executor->receipt);
				if (group.empty())
					coreturn remote_exception("invalid operation");

				uint8_t message_hash[32];
				route->challenge(executor->receipt.transaction_hash, message_hash);
				if (!compositor)
				{
					auto* chain = superchain::bridge::get()->get_network_params(route->asset);
					auto alg = chain ? chain->composition : algorithm::composition::type::unknown;
					auto maybe_compositor = algorithm::composition::make_public_key_compositor(alg, message_hash, sizeof(message_hash), (uint16_t)group.size());
					if (!maybe_compositor)
						coreturn remote_exception(std::move(maybe_compositor.error().message()));

					compositor = std::move(*maybe_compositor);
				}

				auto delegates = coawait(convene_delegates(group));
				if (!delegates)
					coreturn delegates.error();

				if (delegates->size() != group.size())
				{
				postpone:
					compositor.destroy();
					coreturn ++attempt >= protocol::now().user.consensus.coordination_attempts ? remote_exception("failed after multiple attempts") : remote_exception::retry_later();
				}

				for (auto& participant : group)
					encrypted_shares[adapter->get_public_key(participant)] = btree_map<algorithm::pubkeyhash_t, string>();
				
				bool reset = false;
				auto chosen_it = group.begin();
				std::advance(chosen_it, (size_t)(algorithm::hashing::hash256i(message_hash, sizeof(message_hash)) % uint256_t(group.size())));
				auto chosen_participant = *chosen_it;
				while (compositor->steps_left() > 0)
				{
					auto phase = compositor->next_phase();
					if (!reset && (phase == algorithm::composition::phase::any_input_after_reset || phase == algorithm::composition::phase::chosen_input_after_reset))
					{
						delegates = group;
						reset = true;
					}

					bool uniform_input = phase == algorithm::composition::phase::any_input_after_reset || phase == algorithm::composition::phase::any_input;
					bool chosen_input = phase == algorithm::composition::phase::chosen_input_after_reset || phase == algorithm::composition::phase::chosen_input;
					auto it = (uniform_input ? delegates->begin() : (chosen_input ? delegates->find(chosen_participant) : delegates->end()));
					it = (!chosen_input && delegates->size() > 1 && it != delegates->end() && it->equals(chosen_participant) ? ++it : it);
					if (it == delegates->end())
						break;

					auto result = coawait(method_call(*it, bind_delegation, &bind_delegation::aggregate_public_key));
					if (!result && (result.error().is_retry() || result.error().is_shutdown()))
						goto postpone;
					else if (!result)
						coreturn result.error();

					delegates->erase(it);
					reset = false;
				}

				algorithm::composition::cpubkey_t aggregated_public_key, subaggregated_public_key;
				auto status = compositor->derive_public_key(&aggregated_public_key);
				if (!status)
					coreturn remote_exception(std::move(status.error().message()));

				algorithm::composition::chashsig_t aggregated_signature;
				status = compositor->derive_signature(&aggregated_signature);
				if (!status)
					coreturn remote_exception(std::move(status.error().message()));

				delegates = group;
				while (!delegates->empty())
				{
					auto& participant = *delegates->begin();
					auto contribution = key_contributions.find(participant);
					if (contribution == key_contributions.end())
						coreturn remote_exception("failed to find contributing public key of " + algorithm::signing::encode_address(participant));

					if (participant != chosen_participant)
					{
						auto reaggregation = compositor->combine_public_keys(&contribution->second, &subaggregated_public_key);
						if (!reaggregation)
							coreturn remote_exception("failed to verify the aggregated public key: " + reaggregation.what());
					}

					auto result = coawait(method_call(participant, bind_delegation, &bind_delegation::distribute_encrypted_shares));
					if (!result && (result.error().is_retry() || result.error().is_shutdown()))
						goto postpone;
					else if (!result)
						coreturn result.error();

					delegates->erase(participant);
				}

				auto chosen_public_key = key_contributions.find(chosen_participant);
				if (chosen_public_key == key_contributions.end())
					coreturn remote_exception("failed to find contributing public key of " + algorithm::signing::encode_address(chosen_participant));

				algorithm::pubkeyhash_t participant;
				if (!algorithm::signing::recover_hash(key_challenge_hash(message_hash, chosen_public_key->second, aggregated_public_key), participant, key_commitment))
					coreturn remote_exception("failed to verify the contribution public key");

				auto reaggregated_public_key = subaggregated_public_key;
				auto reaggregation = compositor->combine_public_keys(&chosen_public_key->second, &reaggregated_public_key);
				if (!reaggregation || reaggregated_public_key != aggregated_public_key)
					coreturn remote_exception("failed to aggregate the public key from participant contributions: " + reaggregation.what());

				auto* transaction = memory::init<transactions::imbind>();
				transaction->asset = route->asset;
				transaction->set_proof(executor->receipt.transaction_hash, key_commitment, std::move(chosen_public_key->second), std::move(subaggregated_public_key), std::move(aggregated_signature));
				emit_transaction(transaction);
				coreturn expectation::met;
			});
		}
		expects_lr<void> bind_delegation::validate_transition(ledger::delegation_contract* parent, const ledger::wallet& yielding_delegator) const
		{
			auto* prev = (bind_delegation*)parent;
			auto* route = (transactions::route*)executor->transaction;
			if (attempt >= protocol::now().user.consensus.coordination_attempts)
				return layer_exception("invalid attempt counter");

			if (!compositor)
				return layer_exception("invalid compositor");

			if (prev != nullptr)
			{
				if (prev->attempt != attempt)
					return layer_exception("invalid attempt transition");

				if (prev->compositor && !prev->compositor->may_transition_to(**compositor))
					return layer_exception("invalid state machine compositor transition");

				if (prev->encrypted_shares.size() > encrypted_shares.size())
					return layer_exception("invalid encrypted shares transition");

				if (prev->key_contributions.size() > key_contributions.size())
					return layer_exception("invalid key contributions transition");

				if (!prev->key_commitment.empty() && prev->key_commitment != key_commitment)
					return layer_exception("invalid key commitment transition");
			}
			else if (yielding_delegator.public_key_hash != route->get_attester(executor->receipt))
				return layer_exception("invalid attester");

			auto group = route->get_participants(executor->receipt);
			for (auto& [localized_participant_key, localized_encrypted_shares] : encrypted_shares)
			{
				algorithm::pubkeyhash_t localized_participant;
				algorithm::signing::derive_public_key_hash(localized_participant_key, localized_participant);
				if (group.find(localized_participant) == group.end())
					return layer_exception("invalid encrypted shares list");

				for (auto& [participant, encrypted_share] : localized_encrypted_shares)
				{
					if (group.find(participant) == group.end())
						return layer_exception("invalid encrypted share");

					if (prev != nullptr)
					{
						auto a = prev->encrypted_shares.find(localized_participant_key);
						if (a != prev->encrypted_shares.end())
						{
							auto b = a->second.find(participant);
							if (b != a->second.end() && b->second != encrypted_share)
								return layer_exception("invalid encrypted share transition");
						}
					}
				}
			}

			for (auto& [participant, share_public_key] : key_contributions)
			{
				if (group.find(participant) == group.end())
					return layer_exception("invalid contribution public key committer");

				if (prev != nullptr)
				{
					auto it = prev->key_contributions.find(participant);
					if (it != prev->key_contributions.end() && it->second != share_public_key)
						return layer_exception("invalid key contribution transition");
				}
			}

			return expectation::met;
		}
		expects_lr<void> bind_delegation::aggregate_public_key()
		{
			auto* route = (transactions::route*)executor->transaction;
			auto* chain = superchain::bridge::get()->get_network_params(route->asset);
			if (!chain)
				return layer_exception("invalid operation");

			auto secret = adapter->derive_key(runner, executor->receipt.from, route->asset, route->bridge_hash, chain->composition);
			if (!secret)
				return secret.error();

			auto public_key = algorithm::composition::derive_public_key(chain->composition, secret->key);
			if (!public_key)
				return public_key.error();

			auto derivation = compositor->aggregate(secret->key);
			if (!derivation)
				return layer_exception(std::move(derivation.error().message()));

			auto group = route->get_participants(executor->receipt);
			if (group.size() < protocol::now().policy.participation.min_per_account)
				return layer_exception("group is too small");

			size_t group_size = group.size();
			group.erase(runner->public_key_hash);
			key_contributions[runner->public_key_hash] = std::move(*public_key);
			if (!must_complete_encrypted_shares(encrypted_shares, runner, group.size()))
				return expectation::met;

			auto prev_secret = adapter->load_key(runner, executor->receipt.from, route->asset, route->bridge_hash);
			if (prev_secret && prev_secret->key != secret->key)
				return layer_exception("conflicting secret key found (re-aggregation not permitted)");

			btree_set<algorithm::share_t> shares; size_t recovery_group_size = group_size - 1;
			if (!algorithm::signing::split_secret_into_shares(secret->key.data(), secret->key.size(), algorithm::signing::recovery_threshold(group_size), (uint8_t)recovery_group_size, shares) || shares.size() != recovery_group_size)
				return layer_exception("group share derivation failed");

			auto key_check = secret->key;
			memset(key_check.data(), 0, key_check.size());
			if (!algorithm::signing::combine_shares_into_secret(shares, key_check.data(), key_check.size()) || secret->key != key_check)
				return layer_exception("group share recovery check failed");

			auto encrypted_share = encrypted_shares.begin();
			auto finalized_shares = btree_map<algorithm::pubkeyhash_t, ledger::distribution_key::share_pair>();
			for (auto& share : shares)
			{
				if (encrypted_share == encrypted_shares.end())
					return layer_exception("not enough encrypted shares");
				else if (encrypted_share->first == runner->public_key && ++encrypted_share == encrypted_shares.end())
					return layer_exception("not enough encrypted shares");

				algorithm::seckey_t tweak;
				algorithm::signing::derive_secret_key(executor->receipt.transaction_hash, tweak);
				algorithm::pubkey_t tweaked_public_key = encrypted_share->first;
				if (!algorithm::signing::scalar_add_public_key(tweaked_public_key, tweak))
					return layer_exception("invalid tweaked public key");

				auto result = algorithm::signing::public_encrypt(tweaked_public_key, share.view(), algorithm::hashing::hash256i(*crypto::random_bytes(64)));
				if (!result)
					return layer_exception("group share encryption failed");

				algorithm::pubkeyhash_t participant;
				algorithm::signing::derive_public_key_hash(encrypted_share->first, participant);
				encrypted_share->second[runner->public_key_hash] = std::move(*result);
				finalized_shares[participant].sent = share;
				++encrypted_share;
			}

			secret = adapter->store_key(runner, executor->receipt.from, route->asset, route->bridge_hash, std::move(secret->key), std::move(finalized_shares));
			if (!secret)
				return layer_exception(std::move(secret.error().message()));
			
			return expectation::met;
		}
		expects_lr<void> bind_delegation::distribute_encrypted_shares()
		{
			auto* route = (transactions::route*)executor->transaction;
			if (!route)
				return layer_exception("invalid transaction");

			auto localized_encrypted_shares = encrypted_shares.find(runner->public_key);
			if (localized_encrypted_shares == encrypted_shares.end())
				return layer_exception("encrypted shares not found");

			auto secret = adapter->load_key(runner, executor->receipt.from, route->asset, route->bridge_hash);
			if (!secret)
				return layer_exception(std::move(secret.error().message()));

			for (auto& [participant, encrypted_share] : localized_encrypted_shares->second)
			{
				algorithm::seckey_t tweak, tweaked_secret_key = runner->secret_key;
				algorithm::signing::derive_secret_key(executor->receipt.transaction_hash, tweak);
				if (!algorithm::signing::scalar_add_secret_key(tweaked_secret_key, tweak))
					return layer_exception("invalid tweaked secret key");

				auto decrypted_share = algorithm::signing::private_decrypt(tweaked_secret_key, encrypted_share);
				if (!decrypted_share || decrypted_share->size() > sizeof(algorithm::share_t))
					return layer_exception("group share decryption failed");

				secret->shares[participant].recv = algorithm::share_t(*decrypted_share);
			}

			for (auto& [participant, share] : secret->shares)
			{
				if (share.recv.empty())
					return layer_exception(stringify::text("participant %s failed to provide their share", algorithm::signing::encode_address(participant).c_str()));
				else if (share.sent.empty())
					return layer_exception(stringify::text("failed to find self-share for %s", algorithm::signing::encode_address(participant).c_str()));
			}

			secret = adapter->store_key(runner, executor->receipt.from, route->asset, route->bridge_hash, std::move(secret->key), std::move(secret->shares));
			if (!secret)
				return layer_exception(std::move(secret.error().message()));

			auto group = route->get_participants(executor->receipt);
			if (group.empty())
				return layer_exception("invalid operation");

			uint8_t message_hash[32];
			auto chosen = group.begin();
			route->challenge(executor->receipt.transaction_hash, message_hash);
			std::advance(chosen, (size_t)(algorithm::hashing::hash256i(message_hash, sizeof(message_hash)) % uint256_t(group.size())));
			if (*chosen != runner->public_key_hash)
				return expectation::met;

			auto* chain = superchain::bridge::get()->get_network_params(route->asset);
			auto alg = chain ? chain->composition : algorithm::composition::type::unknown;
			auto public_key = algorithm::composition::derive_public_key(alg, secret->key);
			if (!public_key)
				return public_key.error();

			algorithm::composition::cpubkey_t aggregated_public_key;
			auto status = compositor->derive_public_key(&aggregated_public_key);
			if (!status)
				return layer_exception(std::move(status.error().message()));

			if (!algorithm::signing::sign(key_challenge_hash(message_hash, *public_key, aggregated_public_key), runner->secret_key, key_commitment))
				return layer_exception("failed to commit to contribution public key");

			return expectation::met;
		}
		bool bind_delegation::store_payload(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_boolean(!!compositor);
			if (compositor)
				compositor->store(stream);
			stream->write_integer(attempt);
			stream->write_string(key_commitment.optimized_view());
			stream->write_integer((uint8_t)key_contributions.size());
			for (auto& [participant, public_key] : key_contributions)
			{
				stream->write_string(participant.optimized_view());
				stream->write_string(std::string_view((char*)public_key.data(), public_key.size()));
			}
			stream->write_integer((uint8_t)encrypted_shares.size());
			for (auto& [public_key, values] : encrypted_shares)
			{
				stream->write_string(public_key.optimized_view());
				stream->write_integer((uint8_t)values.size());
				for (auto& [participant, value] : values)
				{
					stream->write_string(participant.optimized_view());
					stream->write_string(value);
				}
			}
			return true;
		}
		bool bind_delegation::load_payload(format::ro_stream& stream)
		{
			bool has_compositor = false;
			if (!stream.read_boolean(stream.read_type(), &has_compositor))
				return false;

			auto* chain = superchain::bridge::get()->get_network_params(executor->transaction->asset);
			auto alg = chain ? chain->composition : algorithm::composition::type::unknown;
			auto maybe_compositor = has_compositor ? algorithm::composition::make_compositor_from_stream(alg, stream) : expects_lr<uptr<algorithm::composition::compositor>>(layer_exception());
			if (has_compositor)
			{
				if (!maybe_compositor)
					return false;

				compositor = std::move(*maybe_compositor);
			}
			else
				compositor.destroy();

			if (!stream.read_integer(stream.read_type(), &attempt))
				return false;

			string intermediate;
			if (!stream.read_string(stream.read_type(), &intermediate) || !algorithm::encoding::decode_bytes(intermediate, key_commitment.blob, sizeof(key_commitment)))
				return false;

			uint8_t key_contributions_size;
			if (!stream.read_integer(stream.read_type(), &key_contributions_size))
				return false;

			key_contributions.clear();
			for (uint16_t i = 0; i < key_contributions_size; i++)
			{
				algorithm::pubkeyhash_t participant;
				if (!stream.read_string(stream.read_type(), &intermediate) || !algorithm::encoding::decode_bytes(intermediate, participant.blob, sizeof(participant)))
					return false;

				if (!stream.read_string(stream.read_type(), &intermediate) || intermediate.empty())
					return false;

				auto& public_key = key_contributions[participant];
				public_key.resize(intermediate.size());
				memcpy(public_key.data(), intermediate.data(), intermediate.size());
			}

			uint8_t shares_size;
			if (!stream.read_integer(stream.read_type(), &shares_size))
				return false;

			encrypted_shares.clear();
			for (uint16_t i = 0; i < shares_size; i++)
			{
				algorithm::pubkey_t public_key;
				if (!stream.read_string(stream.read_type(), &intermediate) || !algorithm::encoding::decode_bytes(intermediate, public_key.blob, sizeof(public_key)))
					return false;

				uint8_t values_size;
				if (!stream.read_integer(stream.read_type(), &values_size))
					return false;

				auto& values = encrypted_shares[public_key];
				for (uint16_t j = 0; j < values_size; j++)
				{
					algorithm::pubkeyhash_t participant;
					if (!stream.read_string(stream.read_type(), &intermediate) || !algorithm::encoding::decode_bytes(intermediate, participant.blob, sizeof(participant)))
						return false;

					string encrypted_share;
					if (!stream.read_string(stream.read_type(), &encrypted_share))
						return false;

					values[participant] = std::move(encrypted_share);
				}
			}

			return true;
		}
		ledger::delegation_contract::delegate_ptr bind_delegation::as_delegate_ptr(uint32_t hash) const
		{
			method_bind(hash, bind_delegation, &bind_delegation::aggregate_public_key);
			method_bind(hash, bind_delegation, &bind_delegation::distribute_encrypted_shares);
			return nullptr;
		}
		uint32_t bind_delegation::as_type() const
		{
			return as_instance_type();
		}
		std::string_view bind_delegation::as_typename() const
		{
			return as_instance_typename();
		}
		uint32_t bind_delegation::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view bind_delegation::as_instance_typename()
		{
			return "bind_delegation";
		}
		uint256_t bind_delegation::key_challenge_hash(const uint8_t message_hash[32], const algorithm::composition::cpubkey_t& correction_key, const algorithm::composition::cpubkey_t& corrected_key)
		{
			size_t message_size = 32;
			vector<uint8_t> key_challenge(message_size + correction_key.size() + corrected_key.size(), 0);
			memcpy(key_challenge.data(), message_hash, message_size);
			memcpy(key_challenge.data() + message_size, correction_key.data(), correction_key.size());
			memcpy(key_challenge.data() + message_size + correction_key.size(), corrected_key.data(), corrected_key.size());
			return algorithm::hashing::hash256i(std::string_view((char*)key_challenge.data(), key_challenge.size()));
		}

		rebind_delegation::rebind_delegation(ledger::delegation_adapter* new_adapter, const ledger::executor_context* new_executor, const algorithm::pubkeyhash_t& new_runner) : ledger::delegation_contract(new_adapter, new_executor, new_runner)
		{
		}
		rebind_delegation::rebind_delegation(const rebind_delegation& other) : ledger::delegation_contract(other.adapter, other.executor, other.runner->public_key_hash), proofs(other.proofs)
		{
			context.encrypted_recovery_shares = other.context.encrypted_recovery_shares;
			context.encrypted_shares = other.context.encrypted_shares;
			context.key_contributions = other.context.key_contributions;
			context.key_commitment = other.context.key_commitment;
			context.new_participant_key = other.context.new_participant_key;
			context.accumulator_key = other.context.accumulator_key;
			context.encrypted_accumulator = other.context.encrypted_accumulator;
			context.attempt = other.context.attempt;
			if (other.context.compositor)
				context.compositor = algorithm::composition::make_compositor_from_copy(*other.context.compositor).or_else(nullptr);
		}
		expects_promise_rt<void> rebind_delegation::execute_transition()
		{
			auto* setup = (transactions::setup*)executor->transaction;
			if (!try_running_on(executor->receipt.from))
				return expects_promise_rt<void>(expectation::met);

			auto new_participant = setup->get_new_participant(executor->receipt);
			if (new_participant.empty())
				return expects_promise_rt<void>(expectation::met);
			else if (executor->get_witness_event(executor->receipt.transaction_hash))
				return expects_promise_rt<void>(expectation::met);

			return coasync<expects_rt<void>>([this, setup, new_participant]() -> expects_promise_rt<void>
			{
				auto migrations = setup->get_migration_refs(executor, executor->receipt);
				if (!migrations)
					coreturn remote_exception(std::move(migrations.error().message()));

				for (auto migration_it = migrations->begin() + std::min(migrations->size(), proofs.size()); migration_it != migrations->end(); migration_it++)
				{
					auto& migration = *migration_it;
					auto group = migration.account.group;
					group.erase(migration.old_participant);

					auto retweaking_participant = *group.begin();
					group.insert(new_participant);

					auto delegates = coawait(convene_delegates(group));
					if (!delegates)
						coreturn delegates.error();

					uint8_t attempt = context.attempt;
					if (delegates->size() != group.size())
					{
					postpone:
						context = migration_context();
						context.attempt = attempt;
						coreturn ++context.attempt >= protocol::now().user.consensus.coordination_attempts ? remote_exception("failed after multiple attempts") : remote_exception::retry_later();
					}

					uint8_t message_hash[32];
					auto* chain = superchain::bridge::get()->get_network_params(migration.account.ref.asset);
					auto alg = chain ? chain->composition : algorithm::composition::type::unknown;
					transactions::route::challenge(executor->receipt.transaction_hash, message_hash);

					auto maybe_compositor = algorithm::composition::make_public_key_compositor(alg, message_hash, sizeof(message_hash), (uint16_t)group.size());
					if (!maybe_compositor)
						coreturn remote_exception(std::move(maybe_compositor.error().message()));
				retweak:
					context = migration_context();
					context.attempt = attempt;
					context.new_participant_key = adapter->get_public_key(new_participant);
					context.compositor = std::move(*maybe_compositor);
					for (auto& participant : group)
						context.encrypted_shares[adapter->get_public_key(participant)] = btree_map<algorithm::pubkeyhash_t, string>();

					delegates->erase(new_participant);
					while (!delegates->empty())
					{
						auto prev_encrypted_accumulator = context.encrypted_accumulator;
						auto result = coawait(method_call(*delegates->begin(), rebind_delegation, &rebind_delegation::aggregate_encrypted_shares_and_tweak));
						if (!result && (result.error().is_retry() || result.error().is_shutdown()))
							goto postpone;
						else if (!result)
							coreturn result.error();

						delegates->erase(delegates->begin());
						if (context.accumulator_key.empty())
							coreturn remote_exception("group paillier key not found");
						else if (!prev_encrypted_accumulator.empty() && prev_encrypted_accumulator == context.encrypted_accumulator)
							coreturn remote_exception("group paillier tweak must change");
					}

					auto result = coawait(method_call(new_participant, rebind_delegation, &rebind_delegation::recover_encrypted_shares_and_tweak));
					if (!result && (result.error().is_retry() || result.error().is_shutdown()))
						goto postpone;
					else if (!result)
						coreturn result.error();

					bool reset = false;
					auto chosen_it = group.begin();
					std::advance(chosen_it, (size_t)(algorithm::hashing::hash256i(message_hash, sizeof(message_hash)) % uint256_t(group.size())));
					context.encrypted_recovery_shares.clear();
					while (context.compositor->steps_left() > 0)
					{
						auto phase = context.compositor->next_phase();
						if (!reset && (phase == algorithm::composition::phase::any_input_after_reset || phase == algorithm::composition::phase::chosen_input_after_reset))
						{
							delegates = group;
							reset = true;
						}

						bool uniform_input = phase == algorithm::composition::phase::any_input_after_reset || phase == algorithm::composition::phase::any_input;
						bool chosen_input = phase == algorithm::composition::phase::chosen_input_after_reset || phase == algorithm::composition::phase::chosen_input;
						auto it = (uniform_input ? delegates->begin() : (chosen_input ? delegates->find(*chosen_it) : delegates->end()));
						it = (!chosen_input && delegates->size() > 1 && it != delegates->end() && it->equals(*chosen_it) ? ++it : it);
						if (it == delegates->end())
							break;

						auto result = coawait(method_call(*it, rebind_delegation, &rebind_delegation::aggregate_tweaked_public_key));
						if (!result && (result.error().is_retry() || result.error().is_shutdown()))
							goto postpone;
						else if (!result && *it == retweaking_participant && result.what().find(retweak_phrase()) != string::npos)
							goto retweak;
						else if (!result)
							coreturn result.error();

						delegates->erase(it);
						reset = false;
					}

					algorithm::composition::cpubkey_t aggregated_public_key, subaggregated_public_key;
					auto status = context.compositor->derive_public_key(&aggregated_public_key);
					if (!status)
						coreturn remote_exception(std::move(status.error().message()));

					algorithm::composition::chashsig_t aggregated_signature;
					status = context.compositor->derive_signature(&aggregated_signature);
					if (!status)
						coreturn remote_exception(std::move(status.error().message()));

					delegates = group;
					while (!delegates->empty())
					{
						auto& participant = *delegates->begin();
						auto contribution = context.key_contributions.find(participant);
						if (contribution == context.key_contributions.end())
							coreturn remote_exception("failed to find contributing public key of " + algorithm::signing::encode_address(participant));

						if (participant != new_participant)
						{
							auto reaggregation = context.compositor->combine_public_keys(&contribution->second, &subaggregated_public_key);
							if (!reaggregation)
								coreturn remote_exception("failed to verify the aggregated public key: " + reaggregation.what());
						}

						auto result = coawait(method_call(participant, rebind_delegation, &rebind_delegation::distribute_tweaked_encrypted_shares));
						if (!result && (result.error().is_retry() || result.error().is_shutdown()))
							goto postpone;
						else if (!result)
							coreturn result.error();

						delegates->erase(participant);
					}

					auto new_participant_public_key = context.key_contributions.find(new_participant);
					if (new_participant_public_key == context.key_contributions.end())
						coreturn remote_exception("failed to find contributing public key of " + algorithm::signing::encode_address(new_participant));

					algorithm::pubkeyhash_t participant;
					if (!algorithm::signing::recover_hash(bind_delegation::key_challenge_hash(message_hash, new_participant_public_key->second, aggregated_public_key), participant, context.key_commitment))
						coreturn remote_exception("failed to verify the contribution public key");

					auto reaggregated_public_key = subaggregated_public_key;
					auto reaggregation = context.compositor->combine_public_keys(&new_participant_public_key->second, &reaggregated_public_key);
					if (!reaggregation || reaggregated_public_key != aggregated_public_key)
						coreturn remote_exception("failed to aggregate the public key from participant contributions: " + reaggregation.what());

					migration_proof result_proof;
					result_proof.correction_commitment = context.key_commitment;
					result_proof.correction_key = std::move(new_participant_public_key->second);
					result_proof.imperfect_key = std::move(subaggregated_public_key);
					result_proof.key_commitment = std::move(aggregated_signature);
					proofs.push_back(std::move(result_proof));
				}

				auto* transaction = memory::init<transactions::rebind>();
				transaction->asset = setup->asset;
				for (auto& proof : proofs)
					transaction->add_proof(executor->receipt.transaction_hash, proof.correction_commitment, std::move(proof.correction_key), std::move(proof.imperfect_key), std::move(proof.key_commitment));
				emit_transaction(transaction);
				coreturn expectation::met;
			});
		}
		expects_lr<void> rebind_delegation::validate_transition(ledger::delegation_contract* parent, const ledger::wallet& yielding_delegator) const
		{
			auto* prev = (rebind_delegation*)parent;
			auto* setup = (transactions::setup*)executor->transaction;
			if (context.attempt >= protocol::now().user.consensus.coordination_attempts)
				return layer_exception("invalid attempt counter");

			if (!context.compositor)
				return layer_exception("invalid compositor");

			if (!context.new_participant_key.empty())
			{
				algorithm::pubkeyhash_t new_participant;
				algorithm::signing::derive_public_key_hash(context.new_participant_key, new_participant);
				if (new_participant != setup->get_new_participant(executor->receipt))
					return layer_exception("invalid new participant public key");
			}

			if (!context.encrypted_accumulator.empty() && context.accumulator_key.empty())
				return layer_exception("invalid paillier key");

			for (auto& proof : proofs)
			{
				if (proof.correction_commitment.empty() || proof.correction_key.empty() || proof.imperfect_key.empty() || proof.key_commitment.empty())
					return layer_exception("invalid proof");
			}

			if (!prev)
			{
				if (yielding_delegator.public_key_hash != executor->receipt.from)
					return layer_exception("invalid attester");

				return expectation::met;
			}

			if (!prev->context.accumulator_key.empty() && prev->context.accumulator_key != context.accumulator_key)
				return layer_exception("invalid paillier key");

			if (prev->context.attempt != context.attempt)
				return layer_exception("invalid attempt transition");

			if (context.compositor && prev->context.compositor && !prev->context.compositor->may_transition_to(**context.compositor))
				return layer_exception("invalid state machine compositor transition");

			if (prev->context.encrypted_recovery_shares.size() > context.encrypted_recovery_shares.size())
				return layer_exception("invalid encrypted recovery shares transition");

			if (prev->context.encrypted_shares.size() > context.encrypted_shares.size())
				return layer_exception("invalid encrypted shares transition");

			if (prev->context.key_contributions.size() > context.key_contributions.size())
				return layer_exception("invalid key contributions transition");

			if (!prev->context.key_commitment.empty() && prev->context.key_commitment != context.key_commitment)
				return layer_exception("invalid key commitment transition");

			if (prev->proofs.size() < proofs.size())
				return layer_exception("invalid proofs transition");

			for (auto& [participant, encrypted_recovery_share] : context.encrypted_recovery_shares)
			{
				auto it = prev->context.encrypted_recovery_shares.find(participant);
				if (it != prev->context.encrypted_recovery_shares.end() && it->second != encrypted_recovery_share)
					return layer_exception("invalid encrypted recovery share transition");
			}

			for (auto& [localized_participant_key, localized_encrypted_shares] : context.encrypted_shares)
			{
				for (auto& [participant, encrypted_share] : localized_encrypted_shares)
				{
					auto a = prev->context.encrypted_shares.find(localized_participant_key);
					if (a != prev->context.encrypted_shares.end())
					{
						auto b = a->second.find(participant);
						if (b != a->second.end() && b->second != encrypted_share)
							return layer_exception("invalid encrypted share transition");
					}
				}
			}

			for (auto& [participant, share_public_key] : context.key_contributions)
			{
				auto it = prev->context.key_contributions.find(participant);
				if (it != prev->context.key_contributions.end() && it->second != share_public_key)
					return layer_exception("invalid key contribution transition");
			}

			size_t proofs_size = std::min(prev->proofs.size(), proofs.size());
			for (size_t i = 0; i < proofs_size; i++)
			{
				auto& proof_a = proofs[i];
				auto& proof_b = prev->proofs[i];
				if (proof_a.correction_commitment != proof_b.correction_commitment || proof_a.correction_key != proof_b.correction_key || proof_a.imperfect_key != proof_b.imperfect_key || proof_a.key_commitment != proof_b.key_commitment)
					return layer_exception("invalid proof transition");
			}

			return expectation::met;
		}
		expects_lr<void> rebind_delegation::aggregate_encrypted_shares_and_tweak()
		{
			auto* setup = (transactions::setup*)executor->transaction;
			auto new_participant = setup->get_new_participant(executor->receipt);
			if (new_participant.empty())
				return layer_exception("invalid new participant");

			algorithm::pubkeyhash_t new_participant_check;
			algorithm::signing::derive_public_key_hash(context.new_participant_key, new_participant_check);
			if (new_participant_check != new_participant)
				return layer_exception("invalid new participant key");

			auto migrations = setup->get_migration_refs(executor, executor->receipt);
			if (!migrations)
				return migrations.error();
			else if (proofs.size() >= migrations->size())
				return layer_exception("invalid migration size");

			auto& migration = migrations->at(proofs.size());
			migration.account.group.erase(migration.old_participant);
			if (migration.account.group.empty())
				return layer_exception("invalid migration group");

			auto secret = adapter->load_key(runner, migration.account.ref.owner, migration.account.ref.asset, migration.account.ref.hash);
			if (!secret)
				return secret.error();

			if (runner->public_key_hash != *migration.account.group.begin())
			{
				uint64_t nonce = 0;
				while (true)
				{
					auto individual_tweak = as_individual_tweak(nonce++);
					if (!individual_tweak)
						return individual_tweak.error();

					auto tweaked_key = secret->key;
					auto tweaked_accumulator = context.encrypted_accumulator;
					auto accumulation = context.compositor->tweak_secret_key(context.accumulator_key, tweaking_key_size(), *individual_tweak, &tweaked_key, &tweaked_accumulator);
					if (accumulation)
					{
						context.encrypted_accumulator = std::move(tweaked_accumulator);
						break;
					}
					else if (accumulation.error().message().find("zero") == string::npos)
						return accumulation.error();
				}
			}
			else
			{
				uint8_t seed[64];
				tweaking_seed(runner->secret_key, executor->receipt.transaction_hash, seed);
				auto derivation = context.compositor->derive_tweaking_key(seed, sizeof(seed), tweaking_key_size(), &context.accumulator_key);
				if (!derivation)
					return derivation.error();
			}

			auto it = secret->shares.find(migration.old_participant);
			if (it != secret->shares.end())
			{
				algorithm::seckey_t tweak;
				algorithm::signing::derive_secret_key(executor->receipt.transaction_hash, tweak);
				algorithm::pubkey_t tweaked_public_key = context.new_participant_key;
				if (!algorithm::signing::scalar_add_public_key(tweaked_public_key, tweak))
					return layer_exception("invalid tweaked public key");

				auto result = algorithm::signing::public_encrypt(tweaked_public_key, it->second.recv.view(), algorithm::hashing::hash256i(*crypto::random_bytes(64)));
				if (!result)
					return layer_exception("group share encryption failed");

				context.encrypted_recovery_shares[runner->public_key_hash] = std::move(*result);
			}

			return expectation::met;
		}
		expects_lr<void> rebind_delegation::recover_encrypted_shares_and_tweak()
		{
			auto* setup = (transactions::setup*)executor->transaction;
			if (context.accumulator_key.empty() || context.encrypted_accumulator.empty())
				return layer_exception("invalid group paillier key/tweak");

			algorithm::seckey_t tweak, tweaked_secret_key = runner->secret_key;
			algorithm::signing::derive_secret_key(executor->receipt.transaction_hash, tweak);
			if (!algorithm::signing::scalar_add_secret_key(tweaked_secret_key, tweak))
				return layer_exception("invalid tweaked secret key");

			btree_set<algorithm::share_t> shares;
			for (auto& [participant, encrypted_share] : context.encrypted_recovery_shares)
			{
				auto decrypted_share = algorithm::signing::private_decrypt(tweaked_secret_key, encrypted_share);
				if (!decrypted_share || decrypted_share->empty() || decrypted_share->size() > sizeof(algorithm::share_t))
					return layer_exception("share decryption failed");

				shares.insert(algorithm::share_t(*decrypted_share));
			}

			auto migrations = setup->get_migration_refs(executor, executor->receipt);
			if (!migrations)
				return migrations.error();
			else if (proofs.size() >= migrations->size())
				return layer_exception("invalid migration size");

			auto& migration = migrations->at(proofs.size());
			auto secret = adapter->derive_key(runner, migration.account.ref.owner, migration.account.ref.asset, migration.account.ref.hash, context.compositor->alg_type());
			if (!secret)
				return secret.error();

			if (shares.size() < algorithm::signing::recovery_threshold(migration.account.group.size()))
				return layer_exception("recovery threshold not met");

			if (!algorithm::signing::combine_shares_into_secret(shares, secret->key.data(), secret->key.size()))
				return layer_exception("key recovery failed");

			secret = adapter->store_key(runner, migration.account.ref.owner, migration.account.ref.asset, migration.account.ref.hash, std::move(secret->key), { });
			if (!secret)
				return layer_exception(std::move(secret.error().message()));

			uint64_t nonce = 0;
			while (true)
			{
				auto individual_tweak = as_individual_tweak(nonce++);
				if (!individual_tweak)
					return individual_tweak.error();

				auto tweaked_key = secret->key;
				auto tweaked_accumulator = context.encrypted_accumulator;
				auto accumulation = context.compositor->tweak_secret_key(context.accumulator_key, tweaking_key_size(), *individual_tweak, &tweaked_key, &tweaked_accumulator);
				if (accumulation)
				{
					context.encrypted_accumulator = std::move(tweaked_accumulator);
					break;
				}
				else if (accumulation.error().message().find("zero") == string::npos)
					return accumulation.error();
			}

			return expectation::met;
		}
		expects_lr<void> rebind_delegation::aggregate_tweaked_public_key()
		{
			auto* setup = (transactions::setup*)executor->transaction;
			auto new_participant = setup->get_new_participant(executor->receipt);
			if (new_participant.empty())
				return layer_exception("invalid new participant");

			auto migrations = setup->get_migration_refs(executor, executor->receipt);
			if (!migrations)
				return migrations.error();
			else if (proofs.size() >= migrations->size())
				return layer_exception("invalid migration size");

			auto& migration = migrations->at(proofs.size());
			migration.account.group.erase(migration.old_participant);
			if (migration.account.group.empty())
				return layer_exception("invalid migration group");

			auto secret = adapter->load_key(runner, migration.account.ref.owner, migration.account.ref.asset, migration.account.ref.hash);
			if (!secret)
				return secret.error();

			auto contribution = context.key_contributions.find(runner->public_key_hash);
			if (contribution == context.key_contributions.end())
			{
				if (runner->public_key_hash != *migration.account.group.begin())
				{
					uint64_t nonce = 0;
					while (true)
					{
						auto individual_tweak = as_individual_tweak(nonce++);
						if (!individual_tweak)
							return individual_tweak.error();

						auto tweaked_key = secret->key;
						auto accumulation = context.compositor->tweak_secret_key(context.accumulator_key, tweaking_key_size(), *individual_tweak, &tweaked_key, nullptr);
						if (accumulation)
						{
							secret->key = std::move(tweaked_key);
							break;
						}
						else if (accumulation.error().message().find("zero") == string::npos)
							return accumulation.error();
					}
				}
				else
				{
					uint8_t seed[64];
					tweaking_seed(runner->secret_key, executor->receipt.transaction_hash, seed);
					auto reduction = context.compositor->tweak_secret_key(seed, sizeof(seed), tweaking_key_size(), context.encrypted_accumulator, &secret->key);
					if (!reduction)
						return reduction.error().message().find("zero") == string::npos ? reduction.error() : layer_exception(string(retweak_phrase()));
				}
			}
		
			auto public_key = algorithm::composition::derive_public_key(context.compositor->alg_type(), secret->key);
			if (!public_key)
				return public_key.error();

			auto derivation = context.compositor->aggregate(secret->key);
			if (!derivation)
				return layer_exception(std::move(derivation.error().message()));

			migration.account.group.insert(new_participant);
			if (migration.account.group.size() < protocol::now().policy.participation.min_per_account)
				return layer_exception("group is too small");

			size_t group_size = migration.account.group.size();
			migration.account.group.erase(runner->public_key_hash);
			if (contribution == context.key_contributions.end())
				context.key_contributions.insert(std::make_pair(runner->public_key_hash, std::move(*public_key)));

			if (!must_complete_encrypted_shares(context.encrypted_shares, runner, migration.account.group.size()))
				return expectation::met;

			btree_set<algorithm::share_t> shares; size_t recovery_group_size = group_size - 1;
			if (!algorithm::signing::split_secret_into_shares(secret->key.data(), secret->key.size(), algorithm::signing::recovery_threshold(group_size), (uint8_t)recovery_group_size, shares) || shares.size() != recovery_group_size)
				return layer_exception("group share derivation failed");

			auto key_check = secret->key;
			memset(key_check.data(), 0, key_check.size());
			if (!algorithm::signing::combine_shares_into_secret(shares, key_check.data(), key_check.size()) || secret->key != key_check)
				return layer_exception("group share recovery check failed");

			auto encrypted_share = context.encrypted_shares.begin();
			auto finalized_shares = btree_map<algorithm::pubkeyhash_t, ledger::distribution_key::share_pair>();
			for (auto& share : shares)
			{
				if (encrypted_share == context.encrypted_shares.end())
					return layer_exception("not enough encrypted shares");
				else if (encrypted_share->first == runner->public_key && ++encrypted_share == context.encrypted_shares.end())
					return layer_exception("not enough encrypted shares");

				algorithm::seckey_t tweak;
				algorithm::signing::derive_secret_key(executor->receipt.transaction_hash, tweak);
				algorithm::pubkey_t tweaked_public_key = encrypted_share->first;
				if (!algorithm::signing::scalar_add_public_key(tweaked_public_key, tweak))
					return layer_exception("invalid tweaked public key");

				auto result = algorithm::signing::public_encrypt(tweaked_public_key, share.view(), algorithm::hashing::hash256i(*crypto::random_bytes(64)));
				if (!result)
					return layer_exception("group share encryption failed");

				algorithm::pubkeyhash_t participant;
				algorithm::signing::derive_public_key_hash(encrypted_share->first, participant);
				encrypted_share->second[runner->public_key_hash] = std::move(*result);
				finalized_shares[participant].sent = share;
				++encrypted_share;
			}

			secret = adapter->store_key(runner, algorithm::pubkeyhash_t(), 0, migration.account.ref.hash, std::move(secret->key), std::move(finalized_shares));
			if (!secret)
				return layer_exception(std::move(secret.error().message()));		

			return expectation::met;
		}
		expects_lr<void> rebind_delegation::distribute_tweaked_encrypted_shares()
		{
			auto* setup = (transactions::setup*)executor->transaction;
			if (!setup)
				return layer_exception("invalid transaction");

			auto migrations = setup->get_migration_refs(executor, executor->receipt);
			if (!migrations)
				return migrations.error();
			else if (proofs.size() >= migrations->size())
				return layer_exception("invalid migration size");

			auto& migration = migrations->at(proofs.size());
			auto localized_encrypted_shares = context.encrypted_shares.find(runner->public_key);
			if (localized_encrypted_shares == context.encrypted_shares.end())
				return layer_exception("encrypted shares not found");

			auto secret = adapter->load_key(runner, algorithm::pubkeyhash_t(), 0, migration.account.ref.hash);
			if (!secret)
				return layer_exception(std::move(secret.error().message()));

			for (auto& [participant, encrypted_share] : localized_encrypted_shares->second)
			{
				algorithm::seckey_t tweak, tweaked_secret_key = runner->secret_key;
				algorithm::signing::derive_secret_key(executor->receipt.transaction_hash, tweak);
				if (!algorithm::signing::scalar_add_secret_key(tweaked_secret_key, tweak))
					return layer_exception("invalid tweaked secret key");

				auto decrypted_share = algorithm::signing::private_decrypt(tweaked_secret_key, encrypted_share);
				if (!decrypted_share || decrypted_share->size() > sizeof(algorithm::share_t))
					return layer_exception("group share decryption failed");

				secret->shares[participant].recv = algorithm::share_t(*decrypted_share);
			}

			for (auto& [participant, share] : secret->shares)
			{
				if (share.recv.empty())
					return layer_exception(stringify::text("participant %s failed to provide their share", algorithm::signing::encode_address(participant).c_str()));
				else if (share.sent.empty())
					return layer_exception(stringify::text("failed to find self-share for %s", algorithm::signing::encode_address(participant).c_str()));
			}

			secret = adapter->store_key(runner, migration.account.ref.owner, migration.account.ref.asset, migration.account.ref.hash, std::move(secret->key), std::move(secret->shares));
			if (!secret)
				return layer_exception(std::move(secret.error().message()));

			auto new_participant = setup->get_new_participant(executor->receipt);
			if (new_participant != runner->public_key_hash)
				return expectation::met;

			auto public_key = algorithm::composition::derive_public_key(context.compositor->alg_type(), secret->key);
			if (!public_key)
				return public_key.error();

			algorithm::composition::cpubkey_t aggregated_public_key;
			auto status = context.compositor->derive_public_key(&aggregated_public_key);
			if (!status)
				return layer_exception(std::move(status.error().message()));

			uint8_t message_hash[32];
			transactions::route::challenge(executor->receipt.transaction_hash, message_hash);
			if (!algorithm::signing::sign(bind_delegation::key_challenge_hash(message_hash, *public_key, aggregated_public_key), runner->secret_key, context.key_commitment))
				return layer_exception("failed to commit to contribution public key");

			return expectation::met;
		}
		expects_lr<algorithm::composition::cseckey_t> rebind_delegation::as_individual_tweak(uint64_t nonce) const
		{
			if (!context.compositor)
				return layer_exception("invalid compositor");

			format::wo_stream message;
			message.write_typeless(runner->public_key_hash.blob, sizeof(runner->public_key_hash.blob));
			message.write_typeless(runner->public_key.blob, sizeof(runner->public_key.blob));
			message.write_typeless(runner->secret_key.blob, sizeof(runner->secret_key.blob));
			message.write_typeless(executor->receipt.transaction_hash);
			message.write_typeless(context.attempt);
			message.write_typeless(nonce);

			auto keypair = algorithm::composition::derive_keypair(context.compositor->alg_type(), (uint8_t*)message.data.data(), message.data.size());
			if (!keypair)
				return keypair.error();

			return expects_lr<algorithm::composition::cseckey_t>(std::move(keypair->secret_key));
		}
		bool rebind_delegation::store_payload(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(context.attempt);
			stream->write_string(context.key_commitment.optimized_view());
			stream->write_string(context.new_participant_key.optimized_view());
			stream->write_string(std::string_view((char*)context.accumulator_key.data(), context.accumulator_key.size()));
			stream->write_string(std::string_view((char*)context.encrypted_accumulator.data(), context.encrypted_accumulator.size()));
			stream->write_integer(context.compositor ? (uint8_t)context.compositor->alg_type() : (uint8_t)algorithm::composition::type::unknown);
			if (context.compositor)
				context.compositor->store(stream);
			stream->write_integer((uint8_t)context.key_contributions.size());
			for (auto& [participant, public_key] : context.key_contributions)
			{
				stream->write_string(participant.optimized_view());
				stream->write_string(std::string_view((char*)public_key.data(), public_key.size()));
			}
			stream->write_integer((uint8_t)context.encrypted_shares.size());
			for (auto& [public_key, values] : context.encrypted_shares)
			{
				stream->write_string(public_key.optimized_view());
				stream->write_integer((uint8_t)values.size());
				for (auto& [participant, value] : values)
				{
					stream->write_string(participant.optimized_view());
					stream->write_string(value);
				}
			}
			stream->write_integer((uint8_t)context.encrypted_recovery_shares.size());
			for (auto& [participant, encrypted_share] : context.encrypted_recovery_shares)
			{
				stream->write_string(participant.optimized_view());
				stream->write_string(std::string_view((char*)encrypted_share.data(), encrypted_share.size()));
			}
			stream->write_integer((uint16_t)proofs.size());
			for (auto& proof : proofs)
			{
				stream->write_string(proof.correction_commitment.optimized_view());
				stream->write_string(std::string_view((char*)proof.correction_key.data(), proof.correction_key.size()));
				stream->write_string(std::string_view((char*)proof.imperfect_key.data(), proof.imperfect_key.size()));
				stream->write_string(std::string_view((char*)proof.key_commitment.data(), proof.key_commitment.size()));
			}
			return true;
		}
		bool rebind_delegation::load_payload(format::ro_stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &context.attempt))
				return false;

			string intermediate;
			if (!stream.read_string(stream.read_type(), &intermediate) || !algorithm::encoding::decode_bytes(intermediate, context.key_commitment.blob, sizeof(context.key_commitment)))
				return false;

			if (!stream.read_string(stream.read_type(), &intermediate) || !algorithm::encoding::decode_bytes(intermediate, context.new_participant_key.blob, sizeof(context.new_participant_key)))
				return false;

			if (!stream.read_string(stream.read_type(), &intermediate))
				return false;

			context.accumulator_key.resize(intermediate.size());
			memcpy(context.accumulator_key.data(), intermediate.data(), intermediate.size());
			if (!stream.read_string(stream.read_type(), &intermediate))
				return false;

			algorithm::composition::type alg;
			context.encrypted_accumulator.resize(intermediate.size());
			memcpy(context.encrypted_accumulator.data(), intermediate.data(), intermediate.size());
			if (!stream.read_integer(stream.read_type(), (uint8_t*)&alg))
				return false;

			if (alg != algorithm::composition::type::unknown)
			{
				auto maybe_compositor = algorithm::composition::make_compositor_from_stream(alg, stream);
				if (!maybe_compositor)
					return false;

				context.compositor = std::move(*maybe_compositor);
			}

			uint8_t key_contributions_size;
			if (!stream.read_integer(stream.read_type(), &key_contributions_size))
				return false;

			context.key_contributions.clear();
			for (uint16_t i = 0; i < key_contributions_size; i++)
			{
				algorithm::pubkeyhash_t participant;
				if (!stream.read_string(stream.read_type(), &intermediate) || !algorithm::encoding::decode_bytes(intermediate, participant.blob, sizeof(participant)))
					return false;

				if (!stream.read_string(stream.read_type(), &intermediate) || intermediate.empty())
					return false;

				auto& public_key = context.key_contributions[participant];
				public_key.resize(intermediate.size());
				memcpy(public_key.data(), intermediate.data(), intermediate.size());
			}

			uint8_t shares_size;
			if (!stream.read_integer(stream.read_type(), &shares_size))
				return false;

			context.encrypted_shares.clear();
			for (uint16_t i = 0; i < shares_size; i++)
			{
				algorithm::pubkey_t public_key;
				if (!stream.read_string(stream.read_type(), &intermediate) || !algorithm::encoding::decode_bytes(intermediate, public_key.blob, sizeof(public_key)))
					return false;

				uint8_t values_size;
				if (!stream.read_integer(stream.read_type(), &values_size))
					return false;

				auto& values = context.encrypted_shares[public_key];
				for (uint16_t j = 0; j < values_size; j++)
				{
					algorithm::pubkeyhash_t participant;
					if (!stream.read_string(stream.read_type(), &intermediate) || !algorithm::encoding::decode_bytes(intermediate, participant.blob, sizeof(participant)))
						return false;

					string encrypted_share;
					if (!stream.read_string(stream.read_type(), &encrypted_share))
						return false;

					values[participant] = std::move(encrypted_share);
				}
			}

			uint8_t encrypted_recovery_shares_size;
			if (!stream.read_integer(stream.read_type(), &encrypted_recovery_shares_size))
				return false;

			context.encrypted_recovery_shares.clear();
			for (uint16_t i = 0; i < encrypted_recovery_shares_size; i++)
			{
				algorithm::pubkeyhash_t participant;
				if (!stream.read_string(stream.read_type(), &intermediate) || !algorithm::encoding::decode_bytes(intermediate, participant.blob, sizeof(participant)))
					return false;

				if (!stream.read_string(stream.read_type(), &intermediate) || intermediate.empty())
					return false;

				auto& encrypted_share = context.encrypted_recovery_shares[participant];
				encrypted_share.resize(intermediate.size());
				memcpy(encrypted_share.data(), intermediate.data(), intermediate.size());
			}

			uint16_t proofs_size;
			if (!stream.read_integer(stream.read_type(), &proofs_size))
				return false;

			proofs.clear();
			for (uint16_t i = 0; i < proofs_size; i++)
			{
				migration_proof proof;
				string correction_commitment_assembly;
				if (!stream.read_string(stream.read_type(), &correction_commitment_assembly) || !algorithm::encoding::decode_bytes(correction_commitment_assembly, proof.correction_commitment.blob, sizeof(proof.correction_commitment)))
					return false;

				string correction_key_assembly;
				if (!stream.read_string(stream.read_type(), &correction_key_assembly))
					return false;

				string imperfect_key_assembly;
				if (!stream.read_string(stream.read_type(), &imperfect_key_assembly))
					return false;

				string key_commitment_assembly;
				if (!stream.read_string(stream.read_type(), &key_commitment_assembly))
					return false;

				proof.correction_key.resize(correction_key_assembly.size());
				proof.imperfect_key.resize(imperfect_key_assembly.size());
				proof.key_commitment.resize(key_commitment_assembly.size());
				memcpy(proof.correction_key.data(), correction_key_assembly.data(), correction_key_assembly.size());
				memcpy(proof.imperfect_key.data(), imperfect_key_assembly.data(), imperfect_key_assembly.size());
				memcpy(proof.key_commitment.data(), key_commitment_assembly.data(), key_commitment_assembly.size());
				proofs.push_back(std::move(proof));
			}

			return true;
		}
		ledger::delegation_contract::delegate_ptr rebind_delegation::as_delegate_ptr(uint32_t hash) const
		{
			method_bind(hash, rebind_delegation, &rebind_delegation::aggregate_encrypted_shares_and_tweak);
			method_bind(hash, rebind_delegation, &rebind_delegation::recover_encrypted_shares_and_tweak);
			method_bind(hash, rebind_delegation, &rebind_delegation::aggregate_tweaked_public_key);
			method_bind(hash, rebind_delegation, &rebind_delegation::distribute_tweaked_encrypted_shares);
			return nullptr;
		}
		uint32_t rebind_delegation::as_type() const
		{
			return as_instance_type();
		}
		std::string_view rebind_delegation::as_typename() const
		{
			return as_instance_typename();
		}
		uint32_t rebind_delegation::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view rebind_delegation::as_instance_typename()
		{
			return "rebind_delegation";
		}
		std::string_view rebind_delegation::retweak_phrase()
		{
			return "must re-balance key tweaks";
		}
		size_t rebind_delegation::tweaking_key_size()
		{
			return std::max<size_t>(sizeof(uint256_t) * 8 + protocol::now().policy.participation.max_per_account + 1, 3072);
		}
		void rebind_delegation::tweaking_seed(const algorithm::seckey_t& secret_key, const uint256_t& transaction_hash, uint8_t message[96])
		{
			memcpy(message + 00, secret_key.blob, sizeof(secret_key.blob));
			transaction_hash.encode(message + 32);
		}

		broadcast_delegation::broadcast_delegation(ledger::delegation_adapter* new_adapter, const ledger::executor_context* new_executor, const algorithm::pubkeyhash_t& new_runner) : ledger::delegation_contract(new_adapter, new_executor, new_runner)
		{
		}
		broadcast_delegation::broadcast_delegation(const broadcast_delegation& other) : ledger::delegation_contract(other.adapter, other.executor, other.runner->public_key_hash), attempt(other.attempt)
		{
			if (other.compositor)
				compositor = algorithm::composition::make_compositor_from_copy(*other.compositor).or_else(nullptr);
			if (other.message)
				message = memory::init<superchain::prepared_transaction>(**other.message);
		}
		expects_promise_rt<void> broadcast_delegation::execute_transition()
		{
			auto* withdraw = (transactions::withdraw*)executor->transaction;
			auto attester = withdraw->get_attester(executor->receipt);
			if (attester.empty() || !try_running_on(attester))
				return expects_promise_rt<void>(expectation::met);
			else if (executor->get_witness_event(executor->receipt.transaction_hash))
				return expects_promise_rt<void>(expectation::met);

			auto front = executor->get_bridge_queue(withdraw->asset, withdraw->bridge_hash);
			if (front && front->transaction_hash != executor->receipt.transaction_hash)
				return expects_promise_rt<void>(remote_exception::retry_later());

			return coasync<expects_rt<void>>([this, withdraw]() mutable -> expects_promise_rt<void>
			{
				auto* chain = superchain::bridge::get()->get_network_params(withdraw->asset);
				auto cancel = [this, withdraw](const algorithm::pubkeyhash_t& participant, remote_exception&& error) -> expects_rt<void>
				{
					auto message = string();
					if (!participant.empty())
						message.append("(").append(algorithm::signing::encode_address(participant)).append(") ");
					message.append(error.message());

					auto* transaction = memory::init<transactions::broadcast>();
					transaction->asset = withdraw->asset;
					transaction->set_proof(executor->receipt.transaction_hash, layer_exception(std::move(message)));
					emit_transaction(transaction);
					return expects_rt<void>(std::move(error));
				};

				auto bridge = executor->get_bridge_instance(withdraw->asset, withdraw->bridge_hash);
				if (!bridge)
					coreturn cancel(algorithm::pubkeyhash_t(), remote_exception(std::move(bridge.error().message())));

				if (chain->transaction_expires || !message)
				{
					auto maybe_message = coawait(prepare_transaction(algorithm::asset::base_id_of(withdraw->asset), superchain::wallet_link::from_hash(withdraw->bridge_hash), superchain::value_transfer(withdraw->asset, withdraw->address, decimal(withdraw->value)), bridge->fee_rate));
					if (!maybe_message)
						coreturn maybe_message.error().is_retry() || maybe_message.error().is_shutdown() ? expects_rt<void>(std::move(maybe_message.error())) : cancel(algorithm::pubkeyhash_t(), std::move(maybe_message.error()));
					else if (maybe_message->inputs.size() > std::numeric_limits<uint8_t>::max())
						coreturn cancel(algorithm::pubkeyhash_t(), remote_exception("too many prepared inputs"));

					message = memory::init<superchain::prepared_transaction>(std::move(*maybe_message));
				}

				auto finalization = expects_lr<superchain::finalized_transaction>(layer_exception());
				auto result = expects_rt<void>(remote_exception::shutdown());
				auto* input = message->next_input_for_aggregation();
				while (input != nullptr)
				{
					auto witness = executor->get_witness_account_tagged(withdraw->asset, input->utxo.link.address, 0);
					if (!witness)
						coreturn cancel(algorithm::pubkeyhash_t(), remote_exception(std::move(witness.error().message())));

					auto account = executor->get_bridge_account(witness->ref.owner, witness->ref.asset, witness->ref.hash);
					if (!account)
						coreturn cancel(algorithm::pubkeyhash_t(), remote_exception(std::move(account.error().message())));

					auto delegates = coawait(convene_delegates(account->group));
					if (!delegates)
						coreturn delegates.error().is_retry() || delegates.error().is_shutdown() ? expects_rt<void>(std::move(delegates.error())) : cancel(algorithm::pubkeyhash_t(), std::move(delegates.error()));

					auto chosen = account->group.begin();
					std::advance(chosen, (size_t)(algorithm::hashing::hash256i(input->message.data(), input->message.size()) % uint256_t(account->group.size())));
					if (!compositor)
					{
						auto maybe_compositor = algorithm::composition::make_signature_compositor(input->alg, input->public_key, input->message.data(), input->message.size(), (uint16_t)account->group.size());
						if (!maybe_compositor)
							coreturn cancel(algorithm::pubkeyhash_t(), remote_exception(std::move(maybe_compositor.error().message())));

						compositor = std::move(*maybe_compositor);
					}

					bool reset = false;
					while (true)
					{
						auto phase = compositor->next_phase();
						if (!reset && (phase == algorithm::composition::phase::any_input_after_reset || phase == algorithm::composition::phase::chosen_input_after_reset))
						{
							delegates = account->group;
							reset = true;
						}

						bool uniform_input = phase == algorithm::composition::phase::any_input_after_reset || phase == algorithm::composition::phase::any_input;
						bool chosen_input = phase == algorithm::composition::phase::chosen_input_after_reset || phase == algorithm::composition::phase::chosen_input;
						auto it = (uniform_input ? delegates->begin() : (chosen_input ? delegates->find(*chosen) : delegates->end()));
						it = (!chosen_input && delegates->size() > 1 && it != delegates->end() && it->equals(*chosen) ? ++it : it);
						if (it == delegates->end())
							break;

						auto participant = *it;
						auto subresult = coawait(method_call(participant, broadcast_delegation, &broadcast_delegation::aggregate_signature));
						if (!subresult && (subresult.error().is_retry() || subresult.error().is_shutdown()))
						{
							compositor.destroy();
							coreturn ++attempt >= protocol::now().user.consensus.coordination_attempts ? cancel(participant, remote_exception("failed after multiple attempts")) : expects_rt<void>(remote_exception::retry_later());
						}
						else if (!subresult)
							coreturn cancel(participant, std::move(subresult.error()));
						else
							reset = false;

						delegates->erase(participant);
					}

					input = message->next_input_for_aggregation();
					auto subfinalization = compositor->derive_signature(&input->signature);
					if (!subfinalization)
						coreturn cancel(algorithm::pubkeyhash_t(), remote_exception(std::move(subfinalization.error().message())));

					input = message->next_input_for_aggregation();
					compositor.destroy();
				}

				finalization = finalize_transaction(algorithm::asset::base_id_of(withdraw->asset), std::move(**message));
				if (!finalization)
					coreturn cancel(algorithm::pubkeyhash_t(), remote_exception(std::move(finalization.error().message())));

				result = coawait(broadcast_transaction(algorithm::asset::base_id_of(withdraw->asset), executor->receipt.transaction_hash, superchain::finalized_transaction(*finalization), this));
				if (!result && (result.error().is_retry() || result.error().is_shutdown()))
				{
					compositor.destroy();
					coreturn ++attempt >= protocol::now().user.consensus.coordination_attempts ? cancel(algorithm::pubkeyhash_t(), remote_exception("failed after multiple attempts")) : expects_rt<void>(remote_exception::retry_later());
				}
				else if (!result)
					coreturn cancel(algorithm::pubkeyhash_t(), std::move(result.error()));

				auto* transaction = memory::init<transactions::broadcast>();
				transaction->asset = withdraw->asset;
				transaction->set_proof(executor->receipt.transaction_hash, std::move(*finalization));
				emit_transaction(transaction);
				coreturn expectation::met;
			});
		}
		expects_lr<void> broadcast_delegation::validate_transition(ledger::delegation_contract* parent, const ledger::wallet& yielding_delegator) const
		{
			auto* prev = (broadcast_delegation*)parent;
			auto* withdraw = (transactions::withdraw*)executor->transaction;
			if (attempt >= protocol::now().user.consensus.coordination_attempts)
				return layer_exception("invalid attempt counter");

			if (!message || message->as_status() == superchain::prepared_transaction::status::invalid)
				return layer_exception("invalid message");
			else if (!compositor)
				return layer_exception("invalid compositor");

			if (prev != nullptr)
			{
				if (prev->attempt != attempt)
					return layer_exception("invalid attempt transition");

				if (prev->compositor && !prev->compositor->may_transition_to(**compositor))
					return layer_exception("invalid state machine compositor transition");

				if (prev->message && (!message || message->as_hash() != prev->message->as_hash()))
					return layer_exception("invalid message transition");
			}
			else if (yielding_delegator.public_key_hash != withdraw->get_attester(executor->receipt))
				return layer_exception("invalid attester");

			auto validation = transactions::broadcast::validate_possible_proof(executor, withdraw, executor->receipt, **message);
			if (!validation)
				return layer_exception(std::move(validation.error().message()));

			return expectation::met;
		}
		expects_lr<void> broadcast_delegation::aggregate_signature()
		{
			auto* withdraw = (transactions::withdraw*)executor->transaction;
			auto* input = message->next_input_for_aggregation();
			if (!input)
				return layer_exception("invalid operation");

			auto witness = executor->get_witness_account_tagged(withdraw->asset, input->utxo.link.address, 0);
			if (!witness)
				return layer_exception(std::move(witness.error().message()));

			auto account = executor->get_bridge_account(witness->ref.owner, witness->ref.asset, witness->ref.hash);
			if (!account)
				return expectation::met;

			auto secret = adapter->load_key(runner, account->ref.owner, account->ref.asset, account->ref.hash);
			if (!secret)
				return layer_exception(std::move(secret.error().message()));

			auto accumulation = compositor->aggregate(secret->key);
			if (!accumulation)
				return layer_exception(std::move(accumulation.error().message()));

			auto* offchain = superchain::bridge::get();
			bool may_mockup = protocol::now().is(network_type::regtest);
			if (may_mockup && !offchain->has_network(withdraw->asset, true))
			{
				for (auto& output : message->outputs)
				{
					if (output.link.address == mockup_target_broadcast_error())
						return layer_exception("synthetic broadcast error");
				}
			}

			return expectation::met;
		}
		bool broadcast_delegation::store_payload(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			auto* input = message ? message->next_input_for_aggregation() : nullptr;
			stream->write_integer(attempt);
			stream->write_boolean(input && compositor);
			if (input && compositor)
			{
				message->store(stream);
				compositor->store(stream);
			}
			return true;
		}
		bool broadcast_delegation::load_payload(format::ro_stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &attempt))
				return false;

			bool has_message_and_compositor = false;
			if (!stream.read_boolean(stream.read_type(), &has_message_and_compositor))
				return false;

			if (has_message_and_compositor)
			{
				superchain::prepared_transaction possible_message;
				if (!possible_message.load(stream))
					return false;

				auto* input = possible_message.next_input_for_aggregation();
				if (!input)
					return false;

				auto possible_compositor = algorithm::composition::make_compositor_from_stream(input->alg, stream);
				if (!possible_compositor)
					return false;

				compositor = std::move(*possible_compositor);
				message = memory::init<superchain::prepared_transaction>(std::move(possible_message));
			}
			else
			{
				compositor.destroy();
				message.destroy();
			}

			return true;
		}
		ledger::delegation_contract::delegate_ptr broadcast_delegation::as_delegate_ptr(uint32_t hash) const
		{
			method_bind(hash, broadcast_delegation, &broadcast_delegation::aggregate_signature);
			return nullptr;
		}
		uint32_t broadcast_delegation::as_type() const
		{
			return as_instance_type();
		}
		std::string_view broadcast_delegation::as_typename() const
		{
			return as_instance_typename();
		}
		uint32_t broadcast_delegation::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view broadcast_delegation::as_instance_typename()
		{
			return "broadcast_delegation";
		}
		string broadcast_delegation::mockup_target_broadcast_error()
		{
			return "0xbad0000000000000000000000000000000000001";
		}
		string broadcast_delegation::mockup_target_attestate_error()
		{
			return "0xbad0000000000000000000000000000000000002";
		}
		string broadcast_delegation::mockup_target_attestate_absent()
		{
			return "0xbad0000000000000000000000000000000000003";
		}
		expects_promise_rt<superchain::prepared_transaction> broadcast_delegation::prepare_transaction(const algorithm::asset_id& asset, const superchain::wallet_link& from_link, const superchain::value_transfer& to, const decimal& max_fee)
		{
			auto* offchain = superchain::bridge::get();
			bool may_mockup = protocol::now().is(network_type::regtest);
			if (!may_mockup || offchain->has_network(asset, true))
				return offchain->prepare_transaction(asset, from_link, to, max_fee);

			auto chain = offchain->get_network_params(asset);
			if (!chain)
				return expects_promise_rt<superchain::prepared_transaction>(remote_exception("invalid operation"));

			auto from = offchain->normalize_link(asset, from_link);
			if (!from)
				return expects_promise_rt<superchain::prepared_transaction>(remote_exception(std::move(from.error().message())));

			auto message = format::wo_stream();
			if (!from->store_payload(&message))
				return expects_promise_rt<superchain::prepared_transaction>(remote_exception("serialization error"));

			auto public_key = offchain->to_composite_public_key(asset, from->public_key);
			if (!public_key)
				return expects_promise_rt<superchain::prepared_transaction>(remote_exception(std::move(public_key.error().message())));

			auto transfers = hash_map<algorithm::asset_id, decimal>();
			transfers[algorithm::asset::base_id_of(asset)] = decimal("0.000001");

			auto& value = transfers[to.asset];
			value = value.is_nan() ? to.value : (value + to.value);

			uint8_t message_hash[32];
			message.write_integer(to.asset);
			message.write_string(to.address);
			message.write_decimal(to.value);
			message.hash().encode(message_hash);

			superchain::prepared_transaction regtest_prepared;
			regtest_prepared.requires_account_input(chain->composition, std::move(*from), *public_key, message_hash, sizeof(message_hash), std::move(transfers));
			regtest_prepared.requires_account_output(to.address, { { to.asset, to.value } });
			return expects_promise_rt<superchain::prepared_transaction>(std::move(regtest_prepared));
		}
		expects_lr<superchain::finalized_transaction> broadcast_delegation::finalize_transaction(const algorithm::asset_id& asset, superchain::prepared_transaction&& prepared)
		{
			auto* offchain = superchain::bridge::get();
			bool may_mockup = protocol::now().is(network_type::regtest);
			if (!may_mockup || offchain->has_network(asset, true))
				return offchain->finalize_transaction(asset, std::move(prepared));

			auto transaction_id = algorithm::encoding::encode_0xhex256(prepared.as_hash());
			auto block_id = algorithm::hashing::hash256i(transaction_id) % std::numeric_limits<uint32_t>::max();
			auto regtest_finalized = superchain::finalized_transaction(std::move(prepared), string(), std::move(transaction_id), block_id);
			regtest_finalized.calldata = regtest_finalized.as_message().encode();
			return expects_lr<superchain::finalized_transaction>(std::move(regtest_finalized));
		}
		expects_promise_rt<void> broadcast_delegation::broadcast_transaction(const algorithm::asset_id& asset, const uint256_t& external_id, superchain::finalized_transaction&& finalized, ledger::delegation_contract* contract)
		{
			auto* offchain = superchain::bridge::get();
			bool may_mockup = protocol::now().is(network_type::regtest);
			if (!may_mockup || offchain->has_network(asset, true))
			{
				auto preserved = memory::init<superchain::finalized_transaction>(std::move(finalized));
				return offchain->broadcast_transaction(asset, external_id, *preserved).then<expects_rt<void>>([preserved](expects_rt<void>&& status) mutable -> expects_rt<void>
				{
					memory::deinit(preserved);
					if (!status)
						return expects_rt<void>(std::move(status.error()));

					return expects_rt<void>(expectation::met);
				});
			}

			if (contract != nullptr && (finalized.prepared.outputs.size() != 1 || finalized.prepared.outputs.front().link.address != mockup_target_attestate_absent()))
			{
				auto* transaction = memory::init<transactions::attestate>();
				transaction->asset = asset;
				transaction->set_gas(decimal::zero(), 0);
				transaction->set_computed_proof(finalized.as_computed(), { });
				transaction->proof.reverted = finalized.prepared.outputs.front().link.address == mockup_target_attestate_error();
				contract->emit_transaction(transaction);
			}
			return expects_promise_rt<void>(expectation::met);
		}

		ledger::delegation_contract* resolver::from_stream(format::ro_stream& stream, ledger::delegation_adapter* adapter, const ledger::executor_context* executor, const algorithm::pubkeyhash_t& delegator)
		{
			uint32_t type; size_t seek = stream.seek;
			if (!stream.read_integer(stream.read_type(), &type))
				return nullptr;

			stream.seek = seek;
			return from_type(type, adapter, executor, delegator);
		}
		ledger::delegation_contract* resolver::from_type(uint32_t hash, ledger::delegation_adapter* adapter, const ledger::executor_context* executor, const algorithm::pubkeyhash_t& delegator)
		{
			if (hash == rebind_delegation::as_instance_type())
				return memory::init<rebind_delegation>(adapter, executor, delegator);
			else if (hash == bind_delegation::as_instance_type())
				return memory::init<bind_delegation>(adapter, executor, delegator);
			else if (hash == broadcast_delegation::as_instance_type())
				return memory::init<broadcast_delegation>(adapter, executor, delegator);
			return nullptr;
		}
		ledger::delegation_contract* resolver::from_copy(const ledger::delegation_contract* base)
		{
			uint32_t hash = base->as_type();
			if (hash == rebind_delegation::as_instance_type())
				return memory::init<rebind_delegation>(*(const rebind_delegation*)base);
			else if (hash == bind_delegation::as_instance_type())
				return memory::init<bind_delegation>(*(const bind_delegation*)base);
			else if (hash == broadcast_delegation::as_instance_type())
				return memory::init<broadcast_delegation>(*(const broadcast_delegation*)base);
			return nullptr;
		}
	}
}