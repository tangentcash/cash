#include "transaction.h"
#include "block.h"

namespace tangent
{
	namespace ledger
	{
		expects_lr<void> transaction::validate(uint64_t block_number) const
		{
			uint64_t expiry_number = algorithm::asset::expiry_of(asset);
			if (!expiry_number)
				return layer_exception("invalid asset");
			else if (block_number > expiry_number)
				return layer_exception("asset is no longer supported");

			if (nonce >= std::numeric_limits<uint64_t>::max() - 1)
				return layer_exception("invalid nonce");

			if (!gas_limit)
				return layer_exception("gas limit requirement not met (min: 1)");

			uint256_t max_gas_limit = block::get_gas_limit();
			if (gas_limit > max_gas_limit)
				return layer_exception("gas limit requirement not met (max: " + max_gas_limit.to_string() + ")");

			if (gas_price.is_nan() || gas_price.is_negative())
				return layer_exception("invalid gas price");

			if (signature.empty())
				return layer_exception("invalid signature");

			return expectation::met;
		}
		expects_lr<void> transaction::execute(transaction_context* context) const
		{
			auto nonce_requirement = context->verify_account_nonce();
			if (!nonce_requirement)
				return nonce_requirement;

			return context->verify_gas_transfer_balance();
		}
		expects_promise_rt<void> transaction::dispatch(const transaction_context* context, dispatch_context* dispatcher) const
		{
			return expects_promise_rt<void>(remote_exception("invalid operation"));
		}
		bool transaction::store_payload(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(asset);
			stream->write_decimal(gas_price);
			stream->write_integer(gas_limit);
			stream->write_integer(nonce);
			return store_body(stream);
		}
		bool transaction::load_payload(format::ro_stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &asset))
				return false;

			if (!stream.read_decimal(stream.read_type(), &gas_price))
				return false;

			if (!stream.read_integer(stream.read_type(), &gas_limit))
				return false;

			if (!stream.read_integer(stream.read_type(), &nonce))
				return false;

			return load_body(stream);
		}
		bool transaction::recover_many(const transaction_context* context, const receipt& receipt, ordered_set<algorithm::pubkeyhash_t>& parties) const
		{
			return true;
		}
		bool transaction::recover_aliases(const transaction_context* context, const receipt& receipt, ordered_set<uint256_t>& aliases) const
		{
			return true;
		}
		bool transaction::sign(const algorithm::seckey_t& secret_key)
		{
			return authentic::sign(secret_key);
		}
		bool transaction::sign(const algorithm::seckey_t& secret_key, uint64_t new_nonce)
		{
			nonce = new_nonce;
			return sign(secret_key);
		}
		bool transaction::sign(const algorithm::seckey_t& secret_key, uint64_t new_nonce, const decimal& price)
		{
			set_gas(price, block::get_gas_limit());
			if (!sign(secret_key, new_nonce))
				return false;

			auto optimal_gas = ledger::transaction_context::calculate_tx_gas(this);
			if (!optimal_gas || gas_limit == *optimal_gas)
				return true;

			gas_limit = *optimal_gas;
			return sign(secret_key);
		}
		expects_lr<void> transaction::set_optimal_gas(const decimal& price)
		{
			auto optimal_gas = ledger::transaction_context::calculate_tx_gas(this);
			if (!optimal_gas)
				return optimal_gas.error();
			
			set_gas(price, *optimal_gas);
			return expectation::met;
		}
		void transaction::set_gas(const decimal& price, const uint256_t& limit)
		{
			gas_price = price;
			gas_limit = limit;
		}
		void transaction::set_asset(const std::string_view& blockchain, const std::string_view& token, const std::string_view& contract_address)
		{
			asset = algorithm::asset::id_of(blockchain, token, contract_address);
		}
		bool transaction::is_payable() const
		{
			auto level = get_type();
			return level == transaction_level::functional;
		}
		bool transaction::is_consensus() const
		{
			auto level = get_type();
			return level == transaction_level::consensus || level == transaction_level::attestation;
		}
		bool transaction::is_dispatchable() const
		{
			return false;
		}
		bool transaction::is_recoverable() const
		{
			auto level = get_type();
			return level != transaction_level::attestation;
		}
		transaction_level transaction::get_type() const
		{
			return transaction_level::functional;
		}
		uptr<schema> transaction::as_schema() const
		{
			std::string_view category;
			switch (get_type())
			{
				case transaction_level::functional:
					category = "functional";
					break;
				case transaction_level::delegation:
					category = "delegation";
					break;
				case transaction_level::consensus:
					category = "consensus";
					break;
				case transaction_level::attestation:
					category = "attestation";
					break;
				default:
					category = "unknown";
					break;
			}

			schema* data = var::set::object();
			data->set("hash", var::string(algorithm::encoding::encode_0xhex256(as_hash())));
			data->set("signature", signature.empty() ? var::null() : var::string(format::util::encode_0xhex(signature.view())));
			data->set("type", var::string(as_typename()));
			data->set("category", var::string(category));
			data->set("asset", algorithm::asset::serialize(asset));
			data->set("nonce", var::integer(nonce));
			data->set("gas_price", var::decimal(gas_price));
			data->set("gas_limit", algorithm::encoding::serialize_uint256(gas_limit));
			return data;
		}

		expects_lr<void> delegation_transaction::validate(uint64_t block_number) const
		{
			if (manager.empty())
				return layer_exception("invalid manager");

			return ledger::transaction::validate(block_number);
		}
		expects_lr<void> delegation_transaction::execute(transaction_context* context) const
		{
			auto nonce_requirement = context->verify_account_nonce();
			if (!nonce_requirement)
				return nonce_requirement;

			if (!is_delegation())
				return expectation::met;

			auto delegation_requirement = context->verify_account_delegation(manager);
			if (!delegation_requirement)
				return delegation_requirement;

			auto delegation = context->apply_account_delegation(manager, 1);
			if (!delegation)
				return delegation.error();

			return expectation::met;
		}
		bool delegation_transaction::store_payload(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(asset);
			stream->write_decimal(gas_price);
			stream->write_integer(gas_limit);
			stream->write_integer(nonce);
			stream->write_string(manager.optimized_view());
			return store_body(stream);
		}
		bool delegation_transaction::load_payload(format::ro_stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &asset))
				return false;

			if (!stream.read_decimal(stream.read_type(), &gas_price))
				return false;

			if (!stream.read_integer(stream.read_type(), &gas_limit))
				return false;

			if (!stream.read_integer(stream.read_type(), &nonce))
				return false;

			string manager_assembly;
			if (!stream.read_string(stream.read_type(), &manager_assembly) || !algorithm::encoding::decode_bytes(manager_assembly, manager.data, sizeof(manager.data)))
				return false;

			return load_body(stream);
		}
		void delegation_transaction::set_manager(const algorithm::pubkeyhash_t& new_manager)
		{
			manager = new_manager;
		}
		bool delegation_transaction::is_delegation() const
		{
			return !gas_price.is_positive();
		}
		uptr<schema> delegation_transaction::as_schema() const
		{
			schema* data = ledger::transaction::as_schema().reset();
			data->set("manager", algorithm::signing::serialize_address(manager));
			return data;
		}
		transaction_level delegation_transaction::get_type() const
		{
			return transaction_level::delegation;
		}

		expects_lr<void> consensus_transaction::execute(transaction_context* context) const
		{
			return context->verify_account_nonce();
		}
		bool consensus_transaction::store_payload(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(asset);
			stream->write_decimal(gas_price);
			stream->write_integer(gas_limit);
			stream->write_integer(nonce);
			return store_body(stream);
		}
		bool consensus_transaction::load_payload(format::ro_stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &asset))
				return false;

			if (!stream.read_decimal(stream.read_type(), &gas_price))
				return false;

			if (!stream.read_integer(stream.read_type(), &gas_limit))
				return false;

			if (!stream.read_integer(stream.read_type(), &nonce))
				return false;

			return load_body(stream);
		}
		transaction_level consensus_transaction::get_type() const
		{
			return transaction_level::consensus;
		}

		expects_lr<void> attestation_transaction::validate(uint64_t block_number) const
		{
			uint64_t expiry_number = algorithm::asset::expiry_of(asset);
			if (!expiry_number)
				return layer_exception("invalid asset");
			else if (block_number > expiry_number)
				return layer_exception("asset is no longer supported");

			if (nonce != 0)
				return layer_exception("invalid nonce (neq: 0)");

			if (!gas_limit)
				return layer_exception("gas limit requirement not met (min: 1)");

			uint256_t max_gas_limit = block::get_gas_limit();
			if (gas_limit > max_gas_limit)
				return layer_exception("gas limit requirement not met (max: " + max_gas_limit.to_string() + ")");

			if (gas_price.is_nan() || gas_price.is_negative())
				return layer_exception("invalid gas price");

			if (!signature.empty())
				return layer_exception("invalid signature");

			if (!input_hash)
				return layer_exception("invalid input hash");

			if (output_hashes.empty())
				return layer_exception("invalid output hashes");

			size_t branch_index = 0;
			for (auto& branch : output_hashes)
			{
				++branch_index;
				if (!branch.first)
					return layer_exception(stringify::text("invalid output hash (branch: %i)", (int)branch_index));

				size_t signature_index = 0;
				for (auto& signature : branch.second.signatures)
				{
					algorithm::pubkeyhash_t attester;
					if (!recover_hash(attester, branch.first, signature_index++) || attester.empty())
						return layer_exception(stringify::text("invalid attester (branch: %i, signature: %i)", (int)branch_index, (int)signature_index));
				}
			}

			return expectation::met;
		}
		expects_lr<void> attestation_transaction::execute(transaction_context* context) const
		{
			size_t branch_index = 0;
			for (auto& branch : output_hashes)
			{
				++branch_index;
				if (!branch.first)
					return layer_exception(stringify::text("invalid output hash (branch: %i)", (int)branch_index));

				size_t signature_index = 0;
				for (auto& signature : branch.second.signatures)
				{
					algorithm::pubkeyhash_t attester;
					if (!recover_hash(attester, branch.first, signature_index++))
						return layer_exception(stringify::text("invalid attester (branch: %i, signature: %i)", (int)branch_index, (int)signature_index));

					auto attestation_requirement = context->verify_validator_attestation(asset, attester);
					if (!attestation_requirement)
						return layer_exception(stringify::text("%s (branch: %i, signature: %i)", attestation_requirement.what().c_str(), (int)branch_index, (int)signature_index));
				}
			}

			return expectation::met;
		}
		bool attestation_transaction::merge(const transaction_context* context, const attestation_transaction& other)
		{
			if (asset > 0 && other.asset != asset)
				return false;
			else if (input_hash > 0 && other.input_hash != input_hash)
				return false;

			auto branches = std::move(output_hashes);
			auto* branch_a = get_best_branch(context, nullptr);
			auto* branch_b = other.get_best_branch(context, nullptr);
			size_t branch_length_a = (branch_a ? branch_a->signatures.size() : 0);
			size_t branch_length_b = (branch_b ? branch_b->signatures.size() : 0);
			if (branch_length_a < branch_length_b)
				*this = other;

			asset = other.asset;
			input_hash = other.input_hash;
			output_hashes = std::move(branches);
			if (gas_limit < other.gas_limit)
				gas_limit = other.gas_limit;
			if (gas_price < other.gas_price)
				gas_price = other.gas_price;

			unordered_map<algorithm::hashsig_t, algorithm::pubkeyhash_t> signatures;
			unordered_map<algorithm::pubkeyhash_t, size_t> attesters;
			for (auto& branch : output_hashes)
			{
				uint256_t aggregate_message_hash = get_branch_image(branch.first);
				for (auto& signature : branch.second.signatures)
				{
					auto& attester = signatures[signature];
					if (attester.empty() && !algorithm::signing::recover_hash(aggregate_message_hash, attester, signature))
						return false;

					++attesters[attester];
				}
			}

			for (auto& branch : other.output_hashes)
			{
				uint256_t aggregate_message_hash = other.get_branch_image(branch.first);
				auto& fork = output_hashes[branch.first];
				for (auto& signature : branch.second.signatures)
				{
					auto& attester = signatures[signature];
					if (attester.empty() && !algorithm::signing::recover_hash(aggregate_message_hash, attester, signature))
						return false;

					++attesters[attester];
					fork.signatures.insert(signature);
				}
			}

			for (auto& [attester, votes] : attesters)
			{
				if (votes <= 1)
					continue;

				for (auto it = output_hashes.begin(); it != output_hashes.end();)
				{
					for (auto& [signature, conflicting_attester] : signatures)
					{
						if (conflicting_attester == attester)
							it->second.signatures.erase(signature);
					}

					if (it->second.signatures.empty())
						it = output_hashes.erase(it);
					else
						++it;
				}
			}

			return true;
		}
		bool attestation_transaction::store_payload(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(asset);
			stream->write_decimal(gas_price);
			stream->write_integer(gas_limit);
			stream->write_integer(nonce);
			stream->write_integer(input_hash);
			stream->write_integer((uint16_t)output_hashes.size());
			for (auto& branch : output_hashes)
			{
				stream->write_string(branch.second.message.data);
				stream->write_integer((uint16_t)branch.second.signatures.size());
				for (auto& signature : branch.second.signatures)
					stream->write_string(signature.optimized_view());
			}
			return store_body(stream);
		}
		bool attestation_transaction::load_payload(format::ro_stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &asset))
				return false;

			if (!stream.read_decimal(stream.read_type(), &gas_price))
				return false;

			if (!stream.read_integer(stream.read_type(), &gas_limit))
				return false;

			if (!stream.read_integer(stream.read_type(), &nonce))
				return false;

			if (!stream.read_integer(stream.read_type(), &input_hash))
				return false;

			uint16_t output_hashes_size;
			if (!stream.read_integer(stream.read_type(), &output_hashes_size))
				return false;

			output_hashes.clear();
			for (uint16_t i = 0; i < output_hashes_size; i++)
			{
				format::wo_stream message;
				if (!stream.read_string(stream.read_type(), &message.data))
					return false;

				uint16_t signatures_size;
				if (!stream.read_integer(stream.read_type(), &signatures_size))
					return false;

				ordered_set<algorithm::hashsig_t> signatures;
				for (uint16_t i = 0; i < signatures_size; i++)
				{
					string signature_assembly;
					algorithm::hashsig_t signature;
					if (!stream.read_string(stream.read_type(), &signature_assembly) || !algorithm::encoding::decode_bytes(signature_assembly, signature.data, sizeof(signature.data)))
						return false;

					signatures.insert(signature);
				}

				auto& branch = output_hashes[message.hash()];
				branch.message = std::move(message);
				branch.signatures = std::move(signatures);
			}

			return load_body(stream);
		}
		bool attestation_transaction::sign(const algorithm::seckey_t& secret_key)
		{
			nonce = 0;
			memset(signature.data, 0, sizeof(signature.data));
			if (output_hashes.size() > 1)
				return false;

			auto best_branch = output_hashes.begin();
			algorithm::hashsig_t aggregate_signature;
			if (!algorithm::signing::sign(get_branch_image(best_branch->first), secret_key, aggregate_signature))
				return false;

			best_branch->second.signatures.insert(aggregate_signature);
			return true;
		}
		bool attestation_transaction::sign(const algorithm::seckey_t& secret_key, uint64_t new_nonce)
		{
			return sign(secret_key);
		}
		bool attestation_transaction::sign(const algorithm::seckey_t& secret_key, uint64_t new_nonce, const decimal& price)
		{
			set_gas(price, block::get_gas_limit());
			if (!sign(secret_key, new_nonce))
				return false;

			auto optimal_gas = ledger::transaction_context::calculate_tx_gas(this);
			if (!optimal_gas || gas_limit == *optimal_gas)
				return true;

			gas_limit = *optimal_gas;
			return sign(secret_key);
		}
		bool attestation_transaction::verify(const algorithm::pubkey_t& public_key) const
		{
			for (auto& branch : output_hashes)
			{
				size_t signature_index = 0;
				for (auto& candidate : branch.second.signatures)
				{
					if (verify(public_key, branch.first, signature_index++))
						return true;
				}
			}
			return false;
		}
		bool attestation_transaction::verify(const algorithm::pubkey_t& public_key, const uint256_t& output_hash, size_t index) const
		{
			auto branch = output_hashes.find(output_hash);
			if (branch == output_hashes.end())
				return false;

			if (index >= branch->second.signatures.size())
				return false;

			auto signature = branch->second.signatures.begin();
			for (size_t i = 0; i < index; i++)
				++signature;

			return algorithm::signing::verify(get_branch_image(output_hash), public_key, signature->data);
		}
		bool attestation_transaction::recover(algorithm::pubkey_t& public_key) const
		{
			public_key = algorithm::pubkey_t();
			return false;
		}
		bool attestation_transaction::recover(algorithm::pubkey_t& public_key, const uint256_t& output_hash, size_t index) const
		{
			auto branch = output_hashes.find(output_hash);
			if (branch == output_hashes.end())
				return false;

			if (index >= branch->second.signatures.size())
				return false;

			auto signature = branch->second.signatures.begin();
			for (size_t i = 0; i < index; i++)
				++signature;

			return algorithm::signing::recover(get_branch_image(output_hash), public_key, signature->data);
		}
		bool attestation_transaction::recover_hash(algorithm::pubkeyhash_t& public_key_hash) const
		{
			public_key_hash = algorithm::pubkeyhash_t();
			return false;
		}
		bool attestation_transaction::recover_hash(algorithm::pubkeyhash_t& public_key_hash, const uint256_t& output_hash, size_t index) const
		{
			auto branch = output_hashes.find(output_hash);
			if (branch == output_hashes.end())
				return false;

			if (index >= branch->second.signatures.size())
				return false;

			auto signature = branch->second.signatures.begin();
			for (size_t i = 0; i < index; i++)
				++signature;

			return algorithm::signing::recover_hash(get_branch_image(output_hash), public_key_hash, signature->data);
		}
		expects_lr<void> attestation_transaction::set_optimal_gas(const decimal& price)
		{
			auto optimal_gas = ledger::transaction_context::calculate_tx_gas(this);
			if (!optimal_gas)
				return optimal_gas.error();

			set_gas(price, *optimal_gas);
			return expectation::met;
		}
		void attestation_transaction::set_statement(const uint256_t& new_input_hash, const format::wo_stream& output_message)
		{
			output_hashes.clear();
			output_hashes[output_message.hash()].message = output_message;
			input_hash = new_input_hash;
		}
		void attestation_transaction::set_best_branch(const uint256_t& output_hash)
		{
			auto best = output_hashes.find(output_hash);
			if (best != output_hashes.end())
			{
				evaluation_branch target = std::move(best->second);
				output_hashes.clear();
				output_hashes[output_hash] = std::move(target);
			}
			else
				output_hashes.clear();
		}
		const attestation_transaction::evaluation_branch* attestation_transaction::get_best_branch(const transaction_context* context, ordered_map<algorithm::asset_id, size_t>* aggregators) const
		{
			if (!context)
				return output_hashes.size() == 1 ? &output_hashes.begin()->second : nullptr;

			size_t required_signatures = 0;
			if (aggregators != nullptr)
			{
				auto it = aggregators->find(asset);
				if (it == aggregators->end())
					required_signatures = (*aggregators)[asset] = context->calculate_attesters_size(asset).or_else(0);
				else
					required_signatures = it->second;
			}

			decimal best_branch_stake = -1.0;
			const evaluation_branch* best_branch = nullptr;
			auto& policy = protocol::now().policy;
			for (auto& branch : output_hashes)
			{
				size_t required_branch_signatures = std::min<size_t>(required_signatures, protocol::now().policy.attestation_max_per_transaction);
				double current_branch_threshold = required_branch_signatures > 0 ? ((double)branch.second.signatures.size() / (double)required_branch_signatures) : 0.0;
				if ((aggregators != nullptr && current_branch_threshold < protocol::now().policy.attestation_consensus_threshold) || branch.second.message.data.empty())
					continue;

				decimal branch_stake = decimal::zero();
				uint256_t aggregate_message_hash = get_branch_image(branch.first);
				for (auto& signature : branch.second.signatures)
				{
					algorithm::pubkeyhash_t attester;
					if (algorithm::signing::recover_hash(aggregate_message_hash, attester, signature))
					{
						auto attestation = context->get_validator_attestation(asset, attester);
						if (attestation)
							branch_stake += attestation->get_ranked_stake();
					}
				}

				if (branch_stake > best_branch_stake)
				{
					best_branch = &branch.second;
					best_branch_stake = branch_stake;
				}
			}

			return best_branch;
		}
		uint256_t attestation_transaction::get_branch_image(const uint256_t& output_hash) const
		{
			format::wo_stream message;
			message.write_integer(asset);
			message.write_integer(input_hash);
			message.write_integer(output_hash);
			return message.hash();
		}
		uint256_t attestation_transaction::as_group_hash() const
		{
			format::wo_stream message;
			message.write_integer(asset);
			message.write_integer(input_hash);
			return message.hash();
		}
		transaction_level attestation_transaction::get_type() const
		{
			return transaction_level::attestation;
		}
		uptr<schema> attestation_transaction::as_schema() const
		{
			schema* data = ledger::transaction::as_schema().reset();
			data->set("input_hash", var::string(algorithm::encoding::encode_0xhex256(input_hash)));

			auto* branches = data->set("output_hashes", var::set::object());
			for (auto& branch : output_hashes)
			{
				auto* signatures = branches->set(algorithm::encoding::encode_0xhex256(branch.first), var::set::array());
				for (auto& signature : branch.second.signatures)
					signatures->push(var::string(format::util::encode_0xhex(signature.view())));
			}
			return data;
		}
		format::wo_stream attestation_transaction::as_signable() const
		{
			return format::wo_stream();
		}

		bool receipt::store_payload(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(transaction_hash);
			stream->write_integer(absolute_gas_use);
			stream->write_integer(relative_gas_use);
			stream->write_integer(relative_gas_paid);
			stream->write_integer(generation_time);
			stream->write_integer(finalization_time);
			stream->write_integer(block_number);
			stream->write_boolean(successful);
			stream->write_string(from.optimized_view());
			stream->write_integer((uint16_t)events.size());
			for (auto& item : events)
			{
				stream->write_integer(item.first);
				if (!format::variables_util::serialize_merge_into(item.second, stream))
					return false;
			}
			return true;
		}
		bool receipt::load_payload(format::ro_stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &transaction_hash))
				return false;

			if (!stream.read_integer(stream.read_type(), &absolute_gas_use))
				return false;

			if (!stream.read_integer(stream.read_type(), &relative_gas_use))
				return false;

			if (!stream.read_integer(stream.read_type(), &relative_gas_paid))
				return false;

			if (!stream.read_integer(stream.read_type(), &generation_time))
				return false;

			if (!stream.read_integer(stream.read_type(), &finalization_time))
				return false;

			if (!stream.read_integer(stream.read_type(), &block_number))
				return false;

			if (!stream.read_boolean(stream.read_type(), &successful))
				return false;

			string from_assembly;
			if (!stream.read_string(stream.read_type(), &from_assembly) || !algorithm::encoding::decode_bytes(from_assembly, from.data, sizeof(from.data)))
				return false;

			uint16_t size;
			if (!stream.read_integer(stream.read_type(), &size))
				return false;

			events.clear();
			events.reserve((size_t)size);
			for (uint16_t i = 0; i < size; i++)
			{
				uint32_t type;
				if (!stream.read_integer(stream.read_type(), &type))
					return false;

				format::variables values;
				if (!format::variables_util::deserialize_merge_from(stream, &values))
					return false;

				events.emplace_back(std::make_pair(type, std::move(values)));
			}

			return true;
		}
		void receipt::emit_event(uint32_t type, format::variables&& values)
		{
			events.emplace_back(std::make_pair(type, std::move(values)));
		}
		const format::variables* receipt::find_event(uint32_t type, size_t offset) const
		{
			for (auto& item : events)
			{
				if (item.first == type && !offset--)
					return &item.second;
			}
			return nullptr;
		}
		const format::variables* receipt::reverse_find_event(uint32_t type, size_t offset) const
		{
			for (auto it = events.rbegin(); it != events.rend(); ++it)
			{
				auto& item = *it;
				if (item.first == type && !offset--)
					return &item.second;
			}
			return nullptr;
		}
		option<string> receipt::get_error_messages() const
		{
			string messages;
			size_t offset = 0;
			while (true)
			{
				auto* event = find_event(0, offset++);
				if (event && !event->empty())
					messages.append(event->front().as_blob()).push_back('\n');
				else if (!event)
					break;
			}

			if (messages.empty())
				return optional::none;

			messages.pop_back();
			return messages;
		}
		uptr<schema> receipt::as_schema() const
		{
			schema* data = var::set::object();
			data->set("hash", var::string(algorithm::encoding::encode_0xhex256(as_hash())));
			data->set("transaction_hash", var::string(algorithm::encoding::encode_0xhex256(transaction_hash)));
			data->set("from", algorithm::signing::serialize_address(from));
			data->set("absolute_gas_use", algorithm::encoding::serialize_uint256(absolute_gas_use));
			data->set("relative_gas_use", algorithm::encoding::serialize_uint256(relative_gas_use));
			data->set("relative_gas_paid", algorithm::encoding::serialize_uint256(relative_gas_paid));
			data->set("generation_time", algorithm::encoding::serialize_uint256(generation_time));
			data->set("finalization_time", algorithm::encoding::serialize_uint256(finalization_time));
			data->set("block_number", algorithm::encoding::serialize_uint256(block_number));
			data->set("successful", var::boolean(successful));
			auto* events_data = data->set("events", var::set::array());
			for (auto& item : events)
			{
				auto* event_data = events_data->push(var::set::object());
				event_data->set("event", var::integer(item.first));
				event_data->set("args", format::variables_util::serialize(item.second));
			}
			return data;
		}
		uint32_t receipt::as_type() const
		{
			return as_instance_type();
		}
		std::string_view receipt::as_typename() const
		{
			return as_instance_typename();
		}
		uint32_t receipt::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view receipt::as_instance_typename()
		{
			return "receipt";
		}

		state::state(uint64_t new_block_number, uint64_t new_block_nonce) : block_number(new_block_number), block_nonce(new_block_nonce)
		{
		}
		state::state(const block_header* new_block_header) : block_number(new_block_header ? new_block_header->number : 0), block_nonce(new_block_header ? new_block_header->mutation_count : 0)
		{
		}
		bool state::store(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(as_type());
			stream->write_integer(block_number);
			stream->write_integer(block_nonce);
			return store_payload(stream);
		}
		bool state::load(format::ro_stream& stream)
		{
			uint32_t type;
			if (!stream.read_integer(stream.read_type(), &type) || type != as_type())
				return false;

			if (!stream.read_integer(stream.read_type(), &block_number))
				return false;

			if (!stream.read_integer(stream.read_type(), &block_nonce))
				return false;

			if (!load_payload(stream))
				return false;

			return true;
		}
		bool state::store_optimized(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(as_type());
			stream->write_integer(block_number);
			stream->write_integer(block_nonce);
			return store_data(stream);
		}
		bool state::load_optimized(format::ro_stream& stream)
		{
			uint32_t type;
			if (!stream.read_integer(stream.read_type(), &type) || type != as_type())
				return false;

			if (!stream.read_integer(stream.read_type(), &block_number))
				return false;

			if (!stream.read_integer(stream.read_type(), &block_nonce))
				return false;

			if (!load_data(stream))
				return false;

			return true;
		}
		bool state::is_permanent() const
		{
			return false;
		}

		uniform::uniform(uint64_t new_block_number, uint64_t new_block_nonce) : state(new_block_number, new_block_nonce)
		{
		}
		uniform::uniform(const block_header* new_block_header) : state(new_block_header)
		{
		}
		bool uniform::store_payload(format::wo_stream* stream) const
		{
			if (!store_index(stream))
				return false;

			return store_data(stream);
		}
		bool uniform::load_payload(format::ro_stream& stream)
		{
			if (!load_index(stream))
				return false;

			return load_data(stream);
		}
		uptr<schema> uniform::as_schema() const
		{
			schema* data = var::set::object();
			data->set("hash", var::string(algorithm::encoding::encode_0xhex256(as_hash())));
			data->set("type", var::string(as_typename()));
			data->set("block_number", algorithm::encoding::serialize_uint256(block_number));
			data->set("block_nonce", block_nonce > 0 ? algorithm::encoding::serialize_uint256(block_nonce) : var::set::null());
			data->set("index", var::string(format::util::encode_0xhex(as_index())));
			return data;
		}
		state_level uniform::as_level() const
		{
			return state_level::uniform;
		}
		string uniform::as_index() const
		{
			format::wo_stream message;
			store_index(&message);
			return message.data;
		}

		multiform::multiform(uint64_t new_block_number, uint64_t new_block_nonce) : state(new_block_number, new_block_nonce)
		{
		}
		multiform::multiform(const block_header* new_block_header) : state(new_block_header)
		{
		}
		bool multiform::store_payload(format::wo_stream* stream) const
		{
			if (!store_column(stream))
				return false;

			if (!store_row(stream))
				return false;

			return store_data(stream);
		}
		bool multiform::load_payload(format::ro_stream& stream)
		{
			if (!load_column(stream))
				return false;

			if (!load_row(stream))
				return false;

			return load_data(stream);
		}
		uptr<schema> multiform::as_schema() const
		{
			schema* data = var::set::object();
			data->set("hash", var::string(algorithm::encoding::encode_0xhex256(as_hash())));
			data->set("type", var::string(as_typename()));
			data->set("block_number", algorithm::encoding::serialize_uint256(block_number));
			data->set("block_nonce", block_nonce > 0 ? algorithm::encoding::serialize_uint256(block_nonce) : var::set::null());
			data->set("column", var::string(format::util::encode_0xhex(as_column())));
			data->set("row", var::string(format::util::encode_0xhex(as_row())));
			data->set("rank", algorithm::encoding::serialize_uint256(as_rank()));
			return data;
		}
		state_level multiform::as_level() const
		{
			return state_level::multiform;
		}
		string multiform::as_column() const
		{
			format::wo_stream message;
			store_column(&message);
			return message.data;
		}
		string multiform::as_row() const
		{
			format::wo_stream message;
			store_row(&message);
			return message.data;
		}
	}
}
