#include "transaction.h"
#include "block.h"
#include "mediator.h"

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

			if (!sequence || sequence >= std::numeric_limits<uint64_t>::max() - 1)
				return layer_exception("invalid sequence");

			if (!gas_limit)
				return layer_exception("gas limit requirement not met (min: 1)");

			uint256_t max_gas_limit = block::get_gas_limit();
			if (gas_limit > max_gas_limit)
				return layer_exception("gas limit requirement not met (max: " + max_gas_limit.to_string() + ")");

			if (gas_price.is_nan() || gas_price.is_negative())
				return layer_exception("invalid gas price");

			if (is_signature_null())
				return layer_exception("invalid signature");

			return expectation::met;
		}
		expects_lr<void> transaction::execute(transaction_context* context) const
		{
			auto sequence_requirement = context->verify_account_sequence();
			if (!sequence_requirement)
				return sequence_requirement;

			return context->verify_gas_transfer_balance();
		}
		expects_promise_rt<void> transaction::dispatch(const wallet& proposer, const transaction_context* context, vector<uptr<transaction>>* pipeline) const
		{
			return expects_promise_rt<void>(remote_exception("invalid operation"));
		}
		bool transaction::store_payload(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(asset);
			stream->write_decimal(gas_price);
			stream->write_integer(gas_limit);
			stream->write_integer(sequence);
			stream->write_boolean(conservative);
			return store_body(stream);
		}
		bool transaction::load_payload(format::stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &asset))
				return false;

			if (!stream.read_decimal(stream.read_type(), &gas_price))
				return false;

			if (!stream.read_integer(stream.read_type(), &gas_limit))
				return false;

			if (!stream.read_integer(stream.read_type(), &sequence))
				return false;

			if (!stream.read_boolean(stream.read_type(), &conservative))
				return false;

			return load_body(stream);
		}
		bool transaction::recover_many(const receipt& receipt, ordered_set<string>& parties) const
		{
			return true;
		}
		bool transaction::recover_aliases(const receipt& receipt, ordered_set<uint256_t>& aliases) const
		{
			return true;
		}
		bool transaction::sign(const algorithm::seckey secret_key)
		{
			return authentic::sign(secret_key);
		}
		bool transaction::sign(const algorithm::seckey secret_key, uint64_t new_sequence)
		{
			sequence = new_sequence;
			return sign(secret_key);
		}
		bool transaction::sign(const algorithm::seckey secret_key, uint64_t new_sequence, const decimal& price)
		{
			set_estimate_gas(price);
			if (!sign(secret_key, new_sequence))
				return false;

			auto optimal_gas = ledger::transaction_context::calculate_tx_gas(this);
			if (!optimal_gas || gas_limit == *optimal_gas)
				return true;

			gas_limit = *optimal_gas;
			return sign(secret_key);
		}
		void transaction::set_optimal_gas(const decimal& price)
		{
			auto optimal_gas = ledger::transaction_context::calculate_tx_gas(this);
			if (!optimal_gas)
				optimal_gas = get_gas_estimate();
			set_gas(price, *optimal_gas);
		}
		void transaction::set_estimate_gas(const decimal& price)
		{
			set_gas(price, get_gas_estimate());
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
		bool transaction::is_consensus() const
		{
			auto level = get_type();
			return level == transaction_level::consensus || level == transaction_level::aggregation;
		}
		algorithm::asset_id transaction::get_gas_asset() const
		{
			return algorithm::asset::base_id_of(asset);
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
				case transaction_level::aggregation:
					category = "aggregation";
					break;
				default:
					category = "unknown";
					break;
			}

			schema* data = var::set::object();
			data->set("hash", var::string(algorithm::encoding::encode_0xhex256(as_hash())));
			data->set("signature", var::string(format::util::encode_0xhex(std::string_view((char*)signature, sizeof(signature)))));
			data->set("type", var::string(as_typename()));
			data->set("category", var::string(category));
			data->set("asset", algorithm::asset::serialize(asset));
			data->set("sequence", var::integer(sequence));
			data->set("gas_price", var::decimal(gas_price));
			data->set("gas_limit", algorithm::encoding::serialize_uint256(gas_limit));
			return data;
		}
		uint64_t transaction::get_dispatch_offset() const
		{
			return 0;
		}

		expects_lr<void> delegation_transaction::execute(transaction_context* context) const
		{
			return context->verify_account_sequence();
		}
		transaction_level delegation_transaction::get_type() const
		{
			return transaction_level::delegation;
		}

		expects_lr<void> consensus_transaction::execute(transaction_context* context) const
		{
			auto sequence_requirement = context->verify_account_sequence();
			if (!sequence_requirement)
				return sequence_requirement;

			return context->verify_account_work(context->receipt.from);
		}
		transaction_level consensus_transaction::get_type() const
		{
			return transaction_level::consensus;
		}

		expects_lr<void> aggregation_transaction::validate(uint64_t block_number) const
		{
			uint64_t expiry_number = algorithm::asset::expiry_of(asset);
			if (!expiry_number)
				return layer_exception("invalid asset");
			else if (block_number > expiry_number)
				return layer_exception("asset is no longer supported");

			if (sequence != 0)
				return layer_exception("invalid sequence (neq: 0)");

			if (conservative)
				return layer_exception("transaction should not be conservative");

			if (!gas_limit)
				return layer_exception("gas limit requirement not met (min: 1)");

			uint256_t max_gas_limit = block::get_gas_limit();
			if (gas_limit > max_gas_limit)
				return layer_exception("gas limit requirement not met (max: " + max_gas_limit.to_string() + ")");

			if (gas_price.is_nan() || gas_price.is_negative())
				return layer_exception("invalid gas price");

			if (!is_signature_null())
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
				for (auto& signature : branch.second.attestations)
				{
					++signature_index;
					if (signature.size() != sizeof(algorithm::recsighash))
						return layer_exception(stringify::text("invalid attestation signature (branch: %i, signature: %i)", (int)branch_index, (int)signature_index));

					algorithm::pubkeyhash proposer = { 0 }, null = { 0 };
					if (!recover_hash(proposer, branch.first, signature_index - 1) || !memcmp(proposer, null, sizeof(null)))
						return layer_exception(stringify::text("invalid attestation proposer (branch: %i, signature: %i)", (int)branch_index, (int)signature_index));
				}
			}

			return expectation::met;
		}
		expects_lr<void> aggregation_transaction::execute(transaction_context* context) const
		{
			size_t branch_index = 0;
			for (auto& branch : output_hashes)
			{
				++branch_index;
				if (!branch.first)
					return layer_exception(stringify::text("invalid output hash (branch: %i)", (int)branch_index));

				size_t signature_index = 0;
				for (auto& signature : branch.second.attestations)
				{
					algorithm::pubkeyhash proposer = { 0 };
					if (!recover_hash(proposer, branch.first, signature_index++))
						return layer_exception(stringify::text("invalid attestation proposer (branch: %i, signature: %i)", (int)branch_index, (int)signature_index));

					auto status = context->verify_account_work(proposer);
					if (!status)
						return status;
				}
			}

			return context->verify_account_work(context->receipt.from);
		}
		bool aggregation_transaction::store_payload(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			if (!ledger::transaction::store_payload(stream))
				return false;

			stream->write_integer(input_hash);
			stream->write_integer((uint16_t)output_hashes.size());
			for (auto& branch : output_hashes)
			{
				stream->write_string(branch.second.message.data);
				stream->write_integer((uint16_t)branch.second.attestations.size());
				for (auto& signature : branch.second.attestations)
				{
					if (signature.size() != sizeof(algorithm::recsighash))
						return false;

					stream->write_string(signature);
				}
			}
			return true;
		}
		bool aggregation_transaction::load_payload(format::stream& stream)
		{
			if (!ledger::transaction::load_payload(stream))
				return false;

			if (!stream.read_integer(stream.read_type(), &input_hash))
				return false;

			uint16_t output_hashes_size;
			if (!stream.read_integer(stream.read_type(), &output_hashes_size))
				return false;

			output_hashes.clear();
			for (uint16_t i = 0; i < output_hashes_size; i++)
			{
				format::stream message;
				if (!stream.read_string(stream.read_type(), &message.data))
					return false;

				uint16_t signatures_size;
				if (!stream.read_integer(stream.read_type(), &signatures_size))
					return false;

				ordered_set<string> signatures;
				for (uint16_t i = 0; i < signatures_size; i++)
				{
					string signature;
					if (!stream.read_string(stream.read_type(), &signature) || signature.size() != sizeof(algorithm::recsighash))
						return false;

					signatures.insert(signature);
				}

				auto& branch = output_hashes[message.hash()];
				branch.message = std::move(message);
				branch.attestations = std::move(signatures);
			}

			return true;
		}
		bool aggregation_transaction::sign(const algorithm::seckey secret_key)
		{
			sequence = 0;
			conservative = false;
			memset(signature, 0, sizeof(signature));
			return attestate(secret_key);
		}
		bool aggregation_transaction::sign(const algorithm::seckey secret_key, uint64_t new_sequence)
		{
			return sign(secret_key);
		}
		bool aggregation_transaction::sign(const algorithm::seckey secret_key, uint64_t new_sequence, const decimal& price)
		{
			set_estimate_gas(price);
			if (!sign(secret_key, new_sequence))
				return false;

			size_t transaction_size1 = as_message().data.size();
			auto optimal_gas = ledger::transaction_context::calculate_tx_gas(this);
			if (!optimal_gas || gas_limit == *optimal_gas)
				return true;

			gas_limit = *optimal_gas;
			return sign(secret_key);
		}
		bool aggregation_transaction::verify(const algorithm::pubkey public_key) const
		{
			for (auto& branch : output_hashes)
			{
				size_t signature_index = 0;
				for (auto& candidate : branch.second.attestations)
				{
					if (candidate.size() != sizeof(algorithm::recsighash))
						return false;

					if (verify(public_key, branch.first, signature_index++))
						return true;
				}
			}
			return false;
		}
		bool aggregation_transaction::verify(const algorithm::pubkey public_key, const uint256_t& output_hash, size_t index) const
		{
			auto branch = output_hashes.find(output_hash);
			if (branch == output_hashes.end())
				return false;

			if (index >= branch->second.attestations.size())
				return false;

			auto signature = branch->second.attestations.begin();
			for (size_t i = 0; i < index; i++)
				++signature;

			if (signature->size() != sizeof(algorithm::recsighash))
				return false;

			format::stream message;
			message.write_integer(asset);
			message.write_integer(input_hash);
			message.write_integer(output_hash);
			return algorithm::signing::verify(message.hash(), public_key, (uint8_t*)signature->data());
		}
		bool aggregation_transaction::recover(algorithm::pubkey public_key) const
		{
			for (auto& branch : output_hashes)
			{
				size_t signature_index = 0;
				for (auto& candidate : branch.second.attestations)
				{
					if (candidate.size() != sizeof(algorithm::recsighash))
						return false;

					if (recover(public_key, branch.first, signature_index++))
						return true;
				}
			}

			return false;
		}
		bool aggregation_transaction::recover(algorithm::pubkey public_key, const uint256_t& output_hash, size_t index) const
		{
			auto branch = output_hashes.find(output_hash);
			if (branch == output_hashes.end())
				return false;

			if (index >= branch->second.attestations.size())
				return false;

			auto signature = branch->second.attestations.begin();
			for (size_t i = 0; i < index; i++)
				++signature;

			if (signature->size() != sizeof(algorithm::recsighash))
				return false;

			format::stream message;
			message.write_integer(asset);
			message.write_integer(input_hash);
			message.write_integer(output_hash);
			return algorithm::signing::recover(message.hash(), public_key, (uint8_t*)signature->data());
		}
		bool aggregation_transaction::recover_hash(algorithm::pubkeyhash public_key_hash) const
		{
			for (auto& branch : output_hashes)
			{
				size_t signature_index = 0;
				for (auto& candidate : branch.second.attestations)
				{
					if (candidate.size() != sizeof(algorithm::recsighash))
						return false;

					if (recover_hash(public_key_hash, branch.first, signature_index++))
						return true;
				}
			}

			return false;
		}
		bool aggregation_transaction::recover_hash(algorithm::pubkeyhash public_key_hash, const uint256_t& output_hash, size_t index) const
		{
			auto branch = output_hashes.find(output_hash);
			if (branch == output_hashes.end())
				return false;

			if (index >= branch->second.attestations.size())
				return false;

			auto signature = branch->second.attestations.begin();
			for (size_t i = 0; i < index; i++)
				++signature;

			if (signature->size() != sizeof(algorithm::recsighash))
				return false;

			format::stream message;
			message.write_integer(asset);
			message.write_integer(input_hash);
			message.write_integer(output_hash);
			return algorithm::signing::recover_hash(message.hash(), public_key_hash, (uint8_t*)signature->data());
		}
		bool aggregation_transaction::attestate(const algorithm::seckey secret_key)
		{
			if (output_hashes.size() > 1)
				return false;

			auto genesis_branch = output_hashes.begin();
			format::stream cumulative_message;
			cumulative_message.write_integer(asset);
			cumulative_message.write_integer(input_hash);
			cumulative_message.write_integer(genesis_branch->first);

			algorithm::recsighash cumulative_signature;
			if (!algorithm::signing::sign(cumulative_message.hash(), secret_key, cumulative_signature))
				return false;

			genesis_branch->second.attestations.insert(string((char*)cumulative_signature, sizeof(cumulative_signature)));
			return true;
		}
		bool aggregation_transaction::merge(const transaction_context* context, const aggregation_transaction& other)
		{
			if (asset > 0 && other.asset != asset)
				return false;
			else if (input_hash > 0 && other.input_hash != input_hash)
				return false;

			algorithm::pubkeyhash null = { 0 }, owner = { 0 };
			if (!other.recover_hash(owner) || !memcmp(owner, null, sizeof(null)))
				return false;

			unordered_set<string> proposers;
			auto branches = std::move(output_hashes);
			auto* branch_a = get_cumulative_branch(context);
			auto* branch_b = other.get_cumulative_branch(context);
			size_t branch_length_a = (branch_a ? branch_a->attestations.size() : 0);
			size_t branch_length_b = (branch_b ? branch_b->attestations.size() : 0);
			if (branch_length_a < branch_length_b)
				*this = other;

			asset = other.asset;
			input_hash = other.input_hash;
			output_hashes = std::move(branches);
			if (gas_limit < other.gas_limit)
				gas_limit = other.gas_limit;
			if (gas_price < other.gas_price)
				gas_price = other.gas_price;

			for (auto& branch : output_hashes)
			{
				format::stream cumulative_message;
				cumulative_message.write_integer(asset);
				cumulative_message.write_integer(input_hash);
				cumulative_message.write_integer(branch.first);

				uint256_t cumulative_message_hash = cumulative_message.hash();
				for (auto& signature : branch.second.attestations)
				{
					algorithm::pubkeyhash proposer = { 0 };
					if (signature.size() == sizeof(algorithm::recsighash) && algorithm::signing::recover_hash(cumulative_message_hash, proposer, (uint8_t*)signature.data()))
						proposers.insert(string((char*)proposer, sizeof(proposer)));
				}
			}

			for (auto& branch : other.output_hashes)
			{
				format::stream cumulative_message;
				cumulative_message.write_integer(asset);
				cumulative_message.write_integer(input_hash);
				cumulative_message.write_integer(branch.first);

				uint256_t cumulative_message_hash = cumulative_message.hash();
				auto& fork = output_hashes[branch.first];
				for (auto& signature : branch.second.attestations)
				{
					algorithm::pubkeyhash proposer = { 0 };
					if (signature.size() == sizeof(algorithm::recsighash) && algorithm::signing::recover_hash(cumulative_message_hash, proposer, (uint8_t*)signature.data()) && proposers.find(string((char*)proposer, sizeof(proposer))) == proposers.end())
					{
						proposers.insert(string((char*)proposer, sizeof(proposer)));
						fork.attestations.insert(signature);
					}
				}
			}

			return true;
		}
		bool aggregation_transaction::is_signature_null() const
		{
			algorithm::recsighash null = { 0 };
			for (auto& branch : output_hashes)
			{
				for (auto& candidate : branch.second.attestations)
				{
					if (candidate.size() != sizeof(null) || !memcmp(candidate.data(), null, sizeof(null)))
						return true;
				}
			}
			return memcmp(signature, null, sizeof(null)) == 0;
		}
		bool aggregation_transaction::is_consensus_reached() const
		{
			if (output_hashes.size() != 1)
				return false;

			auto genesis_branch = output_hashes.begin();
			if (genesis_branch->second.attestations.empty())
				return false;

			return genesis_branch->second.message.hash() == genesis_branch->first;
		}
		void aggregation_transaction::set_optimal_gas(const decimal& price)
		{
			auto optimal_gas = ledger::transaction_context::calculate_tx_gas(this);
			if (optimal_gas)
			{
				format::stream message;
				auto blob = string(sizeof(algorithm::recsighash), '0');
				size_t size = (size_t)protocol::now().policy.aggregators_committee_size;
				message.write_integer((uint16_t)output_hashes.size());
				message.write_string(string(sizeof(mediator::incoming_transaction) * 10, '0'));
				message.write_integer((uint16_t)size);
				for (size_t i = 0; i < size; i++)
					message.write_string(blob);

				set_gas(price, *optimal_gas + message.data.size() * (uint64_t)gas_cost::write_byte);
			}
			else
				set_gas(price, get_gas_estimate());
		}
		void aggregation_transaction::set_consensus(const uint256_t& output_hash)
		{
			auto it = output_hashes.find(output_hash);
			if (it == output_hashes.end())
				return output_hashes.clear();

			auto value = std::move(it->second);
			output_hashes.clear();
			output_hashes[output_hash] = std::move(value);
		}
		void aggregation_transaction::set_signature(const algorithm::recsighash new_value)
		{
			VI_ASSERT(new_value != nullptr, "new value should be set");
			memcpy(signature, new_value, sizeof(algorithm::recsighash));
		}
		void aggregation_transaction::set_statement(const uint256_t& new_input_hash, const format::stream& output_message)
		{
			output_hashes.clear();
			output_hashes[output_message.hash()].message = output_message;
			input_hash = new_input_hash;
		}
		const aggregation_transaction::cumulative_branch* aggregation_transaction::get_cumulative_branch(const transaction_context* context) const
		{
			if (!context)
				return output_hashes.size() == 1 ? &output_hashes.begin()->second : nullptr;

			uint256_t best_branch_work = 0;
			const cumulative_branch* best_branch = nullptr;
			auto& policy = protocol::now().policy;
			for (auto& branch : output_hashes)
			{
				format::stream cumulative_message;
				cumulative_message.write_integer(asset);
				cumulative_message.write_integer(input_hash);
				cumulative_message.write_integer(branch.first);

				uint256_t cumulative_message_hash = cumulative_message.hash();
				uint256_t branch_work = 0, work_limit = uint256_t::max() / uint256_t(branch.second.attestations.size());
				for (auto& signature : branch.second.attestations)
				{
					algorithm::pubkeyhash proposer = { 0 };
					if (signature.size() != sizeof(algorithm::recsighash) || !algorithm::signing::recover_hash(cumulative_message_hash, proposer, (uint8_t*)signature.data()))
						continue;

					auto work = context->get_account_work(proposer);
					branch_work += std::min(work ? work->get_gas_use() : uint256_t(0), work_limit);
				}

				if (branch_work > best_branch_work)
				{
					best_branch = &branch.second;
					best_branch_work = branch_work;
				}
			}
			return best_branch;
		}
		option<aggregation_transaction::cumulative_consensus> aggregation_transaction::calculate_cumulative_consensus(ordered_map<algorithm::asset_id, size_t>* aggregators, transaction_context* context) const
		{
			if (!context)
				return optional::none;

			auto* branch = get_cumulative_branch(context);
			if (!branch || branch->attestations.empty())
				return optional::none;

			size_t committee = 0;
			if (aggregators != nullptr)
			{
				auto it = aggregators->find(asset);
				if (it == aggregators->end())
					(*aggregators)[asset] = committee = context->calculate_aggregation_committee_size(asset).or_else(0);
				else
					committee = it->second;
			}
			else
				committee = context->calculate_aggregation_committee_size(asset).or_else(0);

			cumulative_consensus consensus;
			consensus.branch = branch;
			consensus.committee = std::min(committee, protocol::now().policy.aggregators_committee_size);
			consensus.threshold = protocol::now().policy.aggregation_threshold;
			consensus.progress = consensus.committee > 0 ? ((double)branch->attestations.size() / (double)consensus.committee) : 0.0;
			consensus.reached = consensus.progress >= consensus.threshold;
			return consensus;
		}
		uint256_t aggregation_transaction::get_cumulative_hash() const
		{
			format::stream message;
			message.write_integer(asset);
			message.write_integer(input_hash);
			return message.hash();
		}
		transaction_level aggregation_transaction::get_type() const
		{
			return transaction_level::aggregation;
		}
		uptr<schema> aggregation_transaction::as_schema() const
		{
			schema* data = ledger::transaction::as_schema().reset();
			data->set("input_hash", var::string(algorithm::encoding::encode_0xhex256(input_hash)));

			auto* branches = data->set("output_hashes", var::set::object());
			for (auto& branch : output_hashes)
			{
				auto* signatures = branches->set(algorithm::encoding::encode_0xhex256(branch.first), var::set::array());
				for (auto& signature : branch.second.attestations)
					signatures->push(var::string(format::util::encode_0xhex(signature)));
			}
			return data;
		}

		bool receipt::store_payload(format::stream* stream) const
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
			stream->write_string(std::string_view((char*)from, is_from_null() ? 0 : sizeof(from)));
			stream->write_integer((uint16_t)events.size());
			for (auto& item : events)
			{
				stream->write_integer(item.first);
				if (!format::variables_util::serialize_merge_into(item.second, stream))
					return false;
			}
			return true;
		}
		bool receipt::load_payload(format::stream& stream)
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
			if (!stream.read_string(stream.read_type(), &from_assembly) || !algorithm::encoding::decode_uint_blob(from_assembly, from, sizeof(from)))
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
		bool receipt::is_from_null() const
		{
			algorithm::pubkeyhash null = { 0 };
			return memcmp(from, null, sizeof(null)) == 0;
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
		bool state::store(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(version);
			stream->write_integer(as_type());
			stream->write_integer(block_number);
			stream->write_integer(block_nonce);
			return store_payload(stream);
		}
		bool state::load(format::stream& stream)
		{
			auto type = resolve_type(stream, &version);
			if (!type || *type != as_type())
				return false;

			if (!stream.read_integer(stream.read_type(), &block_number))
				return false;

			if (!stream.read_integer(stream.read_type(), &block_nonce))
				return false;

			if (!load_payload(stream))
				return false;

			return true;
		}

		uniform::uniform(uint64_t new_block_number, uint64_t new_block_nonce) : state(new_block_number, new_block_nonce)
		{
		}
		uniform::uniform(const block_header* new_block_header) : state(new_block_header)
		{
		}
		uptr<schema> uniform::as_schema() const
		{
			schema* data = var::set::object();
			data->set("hash", var::string(algorithm::encoding::encode_0xhex256(as_hash())));
			data->set("type", var::string(as_typename()));
			data->set("index", var::string(format::util::encode_0xhex(as_index())));
			data->set("block_number", algorithm::encoding::serialize_uint256(block_number));
			data->set("block_nonce", algorithm::encoding::serialize_uint256(block_nonce));
			return data;
		}
		state_level uniform::as_level() const
		{
			return state_level::uniform;
		}
		string uniform::as_composite() const
		{
			return as_instance_composite(as_index());
		}
		string uniform::as_instance_composite(const std::string_view& index)
		{
			auto composite = string(1 + index.size(), 1);
			memcpy(composite.data() + 1, index.data(), index.size());
			return composite;
		}

		multiform::multiform(uint64_t new_block_number, uint64_t new_block_nonce) : state(new_block_number, new_block_nonce)
		{
		}
		multiform::multiform(const block_header* new_block_header) : state(new_block_header)
		{
		}
		uptr<schema> multiform::as_schema() const
		{
			schema* data = var::set::object();
			data->set("hash", var::string(algorithm::encoding::encode_0xhex256(as_hash())));
			data->set("type", var::string(as_typename()));
			data->set("column", var::string(format::util::encode_0xhex(as_column())));
			data->set("row", var::string(format::util::encode_0xhex(as_row())));
			data->set("factor", var::integer(as_factor()));
			data->set("block_number", algorithm::encoding::serialize_uint256(block_number));
			data->set("block_nonce", algorithm::encoding::serialize_uint256(block_nonce));
			return data;
		}
		state_level multiform::as_level() const
		{
			return state_level::multiform;
		}
		string multiform::as_composite() const
		{
			return as_instance_composite(as_column(), as_row());
		}
		string multiform::as_instance_composite(const std::string_view& column, const std::string_view& row)
		{
			auto composite = string(1 + column.size() + row.size(), 2);
			memcpy(composite.data() + 1, column.data(), column.size());
			memcpy(composite.data() + 1 + column.size(), row.data(), row.size());
			return composite;
		}

		uint256_t gas_util::get_gas_work(const uint128_t& difficulty, const uint256_t& gas_use, const uint256_t& gas_limit, uint64_t priority)
		{
			if (!gas_limit)
				return 0;

			auto& policy = protocol::now().policy;
			uint256_t alignment = 16;
			uint256_t committee = policy.consensus_committee_size;
			uint256_t multiplier = priority >= committee ? 0 : math64u::pow3(committee - priority);
			uint256_t work = (multiplier * gas_use) / gas_limit;
			return work - (work % alignment) + alignment;
		}
		uint256_t gas_util::get_operational_gas_estimate(size_t bytes, size_t operations)
		{
			algorithm::pubkeyhash owner = { 1 };
			static size_t limit = states::account_sequence(owner, 1, 1).as_message().data.size();
			bytes += limit * operations;
			return get_storage_gas_estimate(bytes, bytes);
		}
		uint256_t gas_util::get_storage_gas_estimate(size_t bytes_in, size_t bytes_out)
		{
			const double heap_overhead = 2.0, format_overhead = 1.05;
			bytes_in = (size_t)((double)bytes_in * format_overhead / heap_overhead);
			bytes_out = (size_t)((double)bytes_out * format_overhead / heap_overhead);

			uint256_t gas = bytes_in * (size_t)ledger::gas_cost::write_byte + bytes_out * (size_t)ledger::gas_cost::read_byte;
			gas -= gas % 1000;
			return gas + 1000;
		}
	}
}
