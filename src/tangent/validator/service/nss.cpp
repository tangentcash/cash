#include "nss.h"
#include "../storage/mediatorstate.h"
#include "../backend/bitcoin.h"
#include "../backend/forks/bitcoin.h"
#include "../backend/cardano.h"
#include "../backend/ethereum.h"
#include "../backend/forks/ethereum.h"
#include "../backend/ripple.h"
#include "../backend/solana.h"
#include "../backend/stellar.h"
#include "../backend/tron.h"
#include "../backend/monero.h"
extern "C"
{
#include "../internal/libbitcoin/ecc.h"
}

namespace tangent
{
	namespace nss
	{
		template <typename t>
		static invocation_callback chain(server_node* server)
		{
			return [server](const std::string_view& blockchain) -> bool
			{
				algorithm::asset_id asset = algorithm::asset::id_of(blockchain);
				if (server->has_chain(asset))
					return false;

				server->add_chain<t>(asset);
				return true;
			};
		}

		server_node::server_node() noexcept : control_sys("nss-node")
		{
			auto& chains = get_registrations();
			for (auto& chain : chains)
				chain.second(chain.first);

			auto& config = protocol::now().user.nss.options;
			if (config)
			{
				auto* retry_timeout = config->fetch("strategy.retry_timeout");
				if (retry_timeout != nullptr && retry_timeout->value.is(var_type::integer))
					options.retry_waiting_time_ms = retry_timeout->value.get_integer();

				auto* polling_frequency = config->fetch("strategy.polling_frequency");
				if (polling_frequency != nullptr && polling_frequency->value.is(var_type::integer))
					options.polling_frequency_ms = polling_frequency->value.get_integer();

				auto* block_confirmations = config->fetch("strategy.block_confirmations");
				if (block_confirmations != nullptr && block_confirmations->value.is(var_type::integer))
					options.min_block_confirmations = block_confirmations->value.get_integer();

				auto* protocols = config->get("protocols");
				if (protocols != nullptr)
				{
					for (auto& root : protocols->get_childs())
					{
						algorithm::asset_id asset = algorithm::asset::id_of(root->key);
						auto* peers = root->get("peers");
						if (peers && !peers->empty())
						{
							unordered_map<std::string_view, double> sources;
							for (auto& child : peers->get_childs())
							{
								auto source = child->size() > 0 ? child->get(0)->value.get_string() : child->value.get_string();
								auto throttling = child->size() > 1 ? child->get(1)->value.get_number() : 0.0;
								if (!stringify::is_empty_or_whitespace(source) && throttling >= 0.0)
									sources[source] = 1000.0 / throttling;
							}

							for (auto& source : sources)
							{
								if (add_node(asset, source.first, source.second))
								{
									if (protocol::now().user.nss.server && protocol::now().user.nss.logging)
										VI_INFO("[observer] %s server node %.*s added (limit: %.2f rps)", algorithm::asset::handle_of(asset).c_str(), (int)source.first.size(), source.first.data(), source.second);
								}
								else if (protocol::now().user.nss.logging)
									VI_ERR("[observer] %s server node on %.*s add failed (limit: %.2f rps)", algorithm::asset::handle_of(asset).c_str(), (int)source.first.size(), source.first.data(), source.second);
							}
						}

						auto* props = root->fetch("server.props");
						if (props != nullptr && props->value.get_type() != var_type::null)
						{
							add_specifications(asset, props);
							props->unlink();
						}

						auto* tip = root->fetch("server.tip");
						if (tip != nullptr && tip->value.is(var_type::integer))
							enable_checkpoint_height(asset, tip->value.get_integer());

						block_confirmations = root->fetch("server.delay");
						if (block_confirmations != nullptr && block_confirmations->value.is(var_type::integer))
							options.add_specific_options(root->key).min_block_confirmations = block_confirmations->value.get_integer();
					}
				}
			}
			btc_ecc_start();
		}
		server_node::~server_node() noexcept
		{
			btc_ecc_stop();
		}
		expects_promise_system<http::response_frame> server_node::internal_call(const std::string_view& location, const std::string_view& method, const http::fetch_frame& options)
		{
			return http::fetch(location, method, options);
		}
		expects_promise_rt<mediator::outgoing_transaction> server_node::submit_transaction(const uint256_t& external_id, const algorithm::asset_id& asset, mediator::dynamic_wallet&& wallet, vector<mediator::transferer>&& to, option<mediator::base_fee>&& fee)
		{
			if (!control_sys.is_active())
				coreturn expects_rt<mediator::outgoing_transaction>(remote_exception::shutdown());

			auto blockchain = algorithm::asset::blockchain_of(asset);
			umutex<std::recursive_mutex> unique(control_sys.sync);
			if (connections.find(blockchain) == connections.end())
				coreturn expects_rt<mediator::outgoing_transaction>(remote_exception(stringify::text("%s blockchain operations are disabled", algorithm::asset::handle_of(asset).c_str())));

			transaction_params* params = memory::init<transaction_params>();
			params->asset = std::move(asset);
			params->wallet = std::move(wallet);
			params->to = std::move(to);
			params->fee = std::move(fee);
			params->external_id = external_id;

			auto& state = states[blockchain];
			if (!state)
			{
				state = memory::init<transaction_queue_state>();
				state->blockchain = blockchain;
			}

			auto future = params->future;
			state->queue.push(params);
			dispatch_transaction_queue(*state, params);
			unique.negate();
			coreturn coawait(std::move(future));
		}
		expects_promise_rt<void> server_node::broadcast_transaction(const algorithm::asset_id& asset, const uint256_t& external_id, const mediator::outgoing_transaction& tx_data)
		{
			if (!algorithm::asset::is_valid(asset) || tx_data.transaction.asset != asset)
				coreturn expects_rt<void>(remote_exception("asset not found"));

			if (!tx_data.is_valid())
				coreturn expects_rt<void>(remote_exception("transaction not found"));

			auto* implementation = get_chain(asset);
			if (!implementation)
				coreturn expects_rt<void>(remote_exception("chain not found"));

			storages::mediatorstate state = storages::mediatorstate(__func__, asset);
			auto duplicate_transaction = state.get_transaction(tx_data.transaction.transaction_id, external_id);
			if (duplicate_transaction)
				coreturn expects_rt<void>(expectation::met);

			auto new_transaction = tx_data.transaction;
			new_transaction.transaction_id = implementation->get_checksum_hash(new_transaction.transaction_id);
			new_transaction.block_id = 0;

			state.add_outgoing_transaction(new_transaction, external_id);
			coreturn coawait(implementation->broadcast_transaction(asset, tx_data));
		}
		expects_promise_rt<void> server_node::validate_transaction(const mediator::incoming_transaction& value)
		{
			if (!value.is_valid())
				coreturn expects_rt<void>(remote_exception("transaction not valid"));

			storages::mediatorstate state = storages::mediatorstate(__func__, value.asset);
			if (state.get_transaction(value.transaction_id, 0))
				coreturn expects_rt<void>(expectation::met);

			auto transaction_data = coawait(get_block_transaction(value.asset, value.block_id, std::string_view(), value.transaction_id));
			if (!transaction_data)
				coreturn expects_rt<void>(std::move(transaction_data.error()));

			auto transactions = coawait(get_authentic_transactions(value.asset, value.block_id, std::string_view(), *transaction_data));
			memory::release(*transaction_data);
			if (!transactions)
				coreturn expects_rt<void>(std::move(transactions.error()));

			auto left = value;
			for (auto& item : left.to)
				item.address_index = 0;
			for (auto& item : left.from)
				item.address_index = 0;

			uint256_t hash = left.as_hash();
			for (auto& right : *transactions)
			{
				for (auto& item : right.to)
					item.address_index = 0;
				for (auto& item : right.from)
					item.address_index = 0;
				if (right.as_hash() == hash)
					coreturn expects_rt<void>(expectation::met);
			}
			coreturn expects_rt<void>(remote_exception("transaction not valid"));
		}
		expects_promise_rt<uint64_t> server_node::get_latest_block_height(const algorithm::asset_id& asset)
		{
			if (!algorithm::asset::is_valid(asset))
				coreturn expects_rt<uint64_t>(remote_exception("asset not found"));

			auto* implementation = get_chain(asset);
			if (!implementation)
				coreturn expects_rt<uint64_t>(remote_exception("chain not found"));

			coreturn coawait(implementation->get_latest_block_height(asset));
		}
		expects_promise_rt<schema*> server_node::get_block_transactions(const algorithm::asset_id& asset, uint64_t block_height, string* block_hash)
		{
			if (!algorithm::asset::is_valid(asset))
				coreturn expects_rt<schema*>(remote_exception("asset not found"));

			auto* implementation = get_chain(asset);
			if (!implementation)
				coreturn expects_rt<schema*>(remote_exception("chain not found"));

			coreturn coawait(implementation->get_block_transactions(asset, block_height, block_hash));
		}
		expects_promise_rt<schema*> server_node::get_block_transaction(const algorithm::asset_id& asset, uint64_t block_height, const std::string_view& block_hash, const std::string_view& transaction_id)
		{
			if (!algorithm::asset::is_valid(asset))
				coreturn expects_rt<schema*>(remote_exception("asset not found"));

			if (!block_height || stringify::is_empty_or_whitespace(transaction_id))
				coreturn expects_rt<schema*>(remote_exception("tx not found"));

			auto* implementation = get_chain(asset);
			if (!implementation)
				coreturn expects_rt<schema*>(remote_exception("chain not found"));

			coreturn coawait(implementation->get_block_transaction(asset, block_height, block_hash, transaction_id));
		}
		expects_promise_rt<vector<mediator::incoming_transaction>> server_node::get_authentic_transactions(const algorithm::asset_id& asset, uint64_t block_height, const std::string_view& block_hash, schema* transaction_data)
		{
			if (!algorithm::asset::is_valid(asset))
				coreturn expects_rt<vector<mediator::incoming_transaction>>(remote_exception("asset not found"));

			if (!block_height)
				coreturn expects_rt<vector<mediator::incoming_transaction>>(remote_exception("txs not found"));

			auto* implementation = get_chain(asset);
			if (!implementation)
				coreturn expects_rt<vector<mediator::incoming_transaction>>(remote_exception("chain not found"));

			coreturn coawait(implementation->get_authentic_transactions(asset, block_height, block_hash, transaction_data));
		}
		expects_promise_rt<schema*> server_node::execute_rpc(const algorithm::asset_id& asset, const std::string_view& method, schema_list&& args, mediator::cache_policy cache)
		{
			if (!algorithm::asset::is_valid(asset))
				coreturn expects_rt<schema*>(remote_exception("asset not found"));

			if (method.empty())
				coreturn expects_rt<schema*>(remote_exception("method not found"));

			auto* implementation = get_chain(asset);
			if (!implementation)
				coreturn expects_rt<schema*>(remote_exception("chain not found"));

			coreturn coawait(implementation->execute_rpc(asset, method, std::move(args), cache));
		}
		expects_promise_rt<mediator::outgoing_transaction> server_node::new_transaction(const algorithm::asset_id& asset, const mediator::dynamic_wallet& wallet, const vector<mediator::transferer>& to, option<mediator::base_fee>&& fee)
		{
			if (!algorithm::asset::is_valid(asset))
				coreturn expects_rt<mediator::outgoing_transaction>(remote_exception("asset not found"));

			if (!wallet.is_valid())
				coreturn expects_rt<mediator::outgoing_transaction>(remote_exception("wallet not found"));

			if (to.empty())
				coreturn expects_rt<mediator::outgoing_transaction>(remote_exception("to address not found"));

			for (auto& address : to)
			{
				if (stringify::is_empty_or_whitespace(address.address))
					coreturn expects_rt<mediator::outgoing_transaction>(remote_exception("receiver address not valid"));

				if (!address.value.is_positive())
					coreturn expects_rt<mediator::outgoing_transaction>(remote_exception("receiver quantity not valid"));
			}

			if (fee && !fee->is_valid())
				coreturn expects_rt<mediator::outgoing_transaction>(remote_exception("fee not valid"));

			auto* implementation = get_chain(asset);
			if (!implementation)
				coreturn expects_rt<mediator::outgoing_transaction>(remote_exception("chain not found"));

			if (!implementation->get_chainparams().supports_bulk_transfer && to.size() > 1)
				coreturn expects_rt<mediator::outgoing_transaction>(remote_exception("only one receiver allowed"));

			mediator::base_fee actual_fee = mediator::base_fee(decimal::nan(), decimal::nan());
			if (!fee)
			{
				auto estimated_fee = coawait(estimate_fee(asset, wallet, to));
				if (!estimated_fee)
					coreturn expects_rt<mediator::outgoing_transaction>(std::move(estimated_fee.error()));
				actual_fee = *estimated_fee;
			}
			else
				actual_fee = *fee;

			decimal fee_value = actual_fee.get_fee();
			if (!fee_value.is_positive())
				coreturn expects_rt<mediator::outgoing_transaction>(remote_exception(stringify::text("fee not valid: %s", fee_value.to_string().c_str())));

			coreturn coawait(implementation->new_transaction(asset, wallet, to, actual_fee));
		}
		expects_promise_rt<mediator::transaction_logs> server_node::get_transaction_logs(const algorithm::asset_id& asset, mediator::chain_supervisor_options* options)
		{
			if (!algorithm::asset::is_valid(asset))
				coreturn expects_rt<mediator::transaction_logs>(remote_exception("asset not found"));

			if (!options)
				coreturn expects_rt<mediator::transaction_logs>(remote_exception("options not found"));

			auto* implementation = get_chain(asset);
			if (!implementation)
				coreturn expects_rt<mediator::transaction_logs>(remote_exception("chain not found"));

			auto* provider = get_node(asset);
			if (!provider)
				coreturn expects_rt<mediator::transaction_logs>(remote_exception("node not found"));

			bool is_dry_run = !options->has_latest_block_height();
			storages::mediatorstate state = storages::mediatorstate(__func__, asset);
			implementation->interact = [options](mediator::server_relay* service) { options->state.interactions.insert(service); };
			options->state.interactions.clear();

			auto tip_checkpoint = uptr<schema>(state.get_property("tip_checkpoint"));
			if (tip_checkpoint)
				options->set_checkpoint_from_block((uint64_t)std::max<int64_t>(1, tip_checkpoint->value.get_integer()) - 1);

			auto tip_latest = uptr<schema>(state.get_property("tip_latest"));
			if (tip_latest && (uint64_t)tip_latest->value.get_integer() > options->state.latest_block_height)
				options->set_checkpoint_from_block((uint64_t)tip_latest->value.get_integer());

			auto tip_override = uptr<schema>(state.get_property("tip_override"));
			if (tip_override)
			{
				uint64_t tip = (uint64_t)tip_override->value.get_integer();
				options->state.starting_block_height = tip;
				options->set_checkpoint_from_block(tip);
			}

			if (!options->has_current_block_height())
			{
			retry:
				auto latest_block_height = coawait(implementation->get_latest_block_height(asset));
				if (!latest_block_height)
					coreturn expects_rt<mediator::transaction_logs>(std::move(latest_block_height.error()));
				options->set_checkpoint_to_block(*latest_block_height);
			}

			if (!options->has_next_block_height())
			{
				if (is_dry_run)
					coreturn expects_rt<mediator::transaction_logs>(mediator::transaction_logs());
				else if (!coawait(provider->yield_for_discovery(options)))
					coreturn expects_rt<mediator::transaction_logs>(remote_exception::retry());
				goto retry;
			}

			mediator::transaction_logs logs;
			logs.block_height = tip_override ? (uint64_t)tip_override->value.get_integer() : options->get_next_block_height();
			logs.block_hash = to_string(logs.block_height);

			auto transactions = uptr<schema>(coawait(implementation->get_block_transactions(asset, logs.block_height, &logs.block_hash)));
			if (transactions)
			{
				for (auto& item : transactions->get_childs())
				{
					if (!item->value.is_object())
					{
						auto details = uptr<schema>(coawait(implementation->get_block_transaction(asset, logs.block_height, logs.block_hash, item->value.get_blob())));
						if (!details)
							continue;

						memory::release(item);
						item = *details;
					}

					auto authentics = coawait(implementation->get_authentic_transactions(asset, logs.block_height, logs.block_hash, item));
					if (authentics)
					{
						for (auto& next : *authentics)
							logs.transactions.push_back(std::move(next));
					}
				}
			}

			if (!tip_checkpoint || (uint64_t)tip_checkpoint->value.get_integer() != logs.block_height)
				state.set_property("tip_checkpoint", var::set::integer(logs.block_height));
			if (!tip_latest || (uint64_t)tip_latest->value.get_integer() != options->state.latest_block_height)
				state.set_property("tip_latest", var::set::integer(options->state.latest_block_height));
			if (tip_override)
				state.set_property("tip_override", nullptr);

			unordered_set<string> transaction_ids;
			for (auto& new_transaction : logs.transactions)
			{
				new_transaction.block_id = logs.block_height;
				new_transaction.transaction_id = implementation->get_checksum_hash(new_transaction.transaction_id);
				state.add_incoming_transaction(new_transaction, logs.block_height);
				transaction_ids.insert(algorithm::asset::handle_of(new_transaction.asset) + ":" + new_transaction.transaction_id);
			}

			auto approvals = state.approve_transactions(logs.block_height, implementation->get_chainparams().sync_latency);
			if (approvals && !approvals->empty())
			{
				logs.transactions.reserve(logs.transactions.size() + approvals->size());
				for (auto& new_transaction : *approvals)
				{
					if (transaction_ids.find(algorithm::asset::handle_of(new_transaction.asset) + ":" + new_transaction.transaction_id) == transaction_ids.end())
						logs.transactions.push_back(std::move(new_transaction));
				}
			}

			coreturn expects_rt<mediator::transaction_logs>(std::move(logs));
		}
		expects_promise_rt<mediator::base_fee> server_node::estimate_fee(const algorithm::asset_id& asset, const mediator::dynamic_wallet& wallet, const vector<mediator::transferer>& to, const mediator::fee_supervisor_options& options)
		{
			if (!algorithm::asset::is_valid(asset) || !options.max_blocks || !options.max_transactions)
				coreturn expects_rt<mediator::base_fee>(remote_exception("asset not found"));

			if (!wallet.is_valid())
				coreturn expects_rt<mediator::base_fee>(remote_exception("wallet not found"));

			if (to.empty())
				coreturn expects_rt<mediator::base_fee>(remote_exception("to address not found"));

			for (auto& address : to)
			{
				if (stringify::is_empty_or_whitespace(address.address))
					coreturn expects_rt<mediator::base_fee>(remote_exception("receiver address not valid"));

				if (!address.value.is_positive())
					coreturn expects_rt<mediator::base_fee>(remote_exception("receiver quantity not valid"));
			}

			auto* implementation = get_chain(asset);
			if (!implementation)
				coreturn expects_rt<mediator::base_fee>(remote_exception("chain not found"));

			if (!implementation->get_chainparams().supports_bulk_transfer && to.size() > 1)
				coreturn expects_rt<mediator::base_fee>(remote_exception("only one receiver allowed"));

			int64_t time = ::time(nullptr);
			string fee_key = stringify::text("%s:%i", algorithm::asset::blockchain_of(asset).c_str(), to.size());
			{
				umutex<std::recursive_mutex> unique(control_sys.sync);
				auto it = fees.find(fee_key);
				if (it != fees.end() && it->second.second >= time)
					coreturn expects_rt<mediator::base_fee>(it->second.first);
			}

			auto estimate = coawait(implementation->estimate_fee(asset, wallet, to, options));
			if (!estimate)
				coreturn expects_rt<mediator::base_fee>(std::move(estimate.error()));

			umutex<std::recursive_mutex> unique(control_sys.sync);
			fees[fee_key] = std::make_pair(*estimate, time + (int64_t)protocol::now().user.nss.fee_estimation_seconds);
			coreturn estimate;
		}
		expects_promise_rt<decimal> server_node::calculate_balance(const algorithm::asset_id& asset, const mediator::dynamic_wallet& wallet, option<string>&& address)
		{
			if (!algorithm::asset::is_valid(asset))
				coreturn expects_rt<decimal>(remote_exception("asset not found"));

			auto binding = wallet.get_binding();
			if (!binding || binding->empty())
				coreturn expects_rt<decimal>(remote_exception("binding not found"));

			if (address && stringify::is_empty_or_whitespace(*address))
				coreturn expects_rt<decimal>(remote_exception("address not found"));

			auto* implementation = get_chain(asset);
			if (!implementation)
				coreturn expects_rt<decimal>(remote_exception("chain not found"));

			coreturn coawait(implementation->calculate_balance(asset, wallet, std::move(address)));
		}
		expects_lr<mediator::master_wallet> server_node::new_master_wallet(const algorithm::asset_id& asset, const std::string_view& seeding_key)
		{
			if (!algorithm::asset::is_valid(asset))
				return expects_lr<mediator::master_wallet>(layer_exception("asset not found"));

			string seed = format::util::is_hex_encoding(seeding_key) ? codec::hex_decode(seeding_key) : string(seeding_key);
			if (seed.empty())
				return expects_lr<mediator::master_wallet>(layer_exception("seed not found"));

			auto* implementation = get_chain(asset);
			if (!implementation)
				return expects_lr<mediator::master_wallet>(layer_exception("chain not found"));

			auto result = implementation->new_master_wallet(seed);
			if (result)
			{
				storages::mediatorstate state = storages::mediatorstate(__func__, asset);
				auto status = state.add_master_wallet(*result);
				if (!status)
					return status.error();
			}
			return result;
		}
		expects_lr<mediator::master_wallet> server_node::new_master_wallet(const algorithm::asset_id& asset, const algorithm::seckey private_key)
		{
			format::stream message;
			message.write_integer(asset);
			message.write_string(*crypto::hash_raw(digests::SHA512(), std::string_view((char*)private_key, sizeof(algorithm::seckey))));
			return new_master_wallet(asset, *crypto::hash_raw(digests::SHA512(), message.data));
		}
		expects_lr<mediator::derived_signing_wallet> server_node::new_signing_wallet(const algorithm::asset_id& asset, const mediator::master_wallet& wallet, option<uint64_t>&& address_index)
		{
			if (!algorithm::asset::is_valid(asset))
				return expects_lr<mediator::derived_signing_wallet>(layer_exception("asset not found"));

			if (!wallet.is_valid())
				return expects_lr<mediator::derived_signing_wallet>(layer_exception("wallet not found"));

			auto* implementation = get_chain(asset);
			if (!implementation)
				return expects_lr<mediator::derived_signing_wallet>(layer_exception("chain not found"));

			if (address_index)
			{
				storages::mediatorstate state = storages::mediatorstate(__func__, asset);
				auto result = state.get_derived_wallet(wallet.as_hash(), *address_index);
				if (result)
					return result;
			}
			else
				address_index = wallet.max_address_index + 1;

			auto result = implementation->new_signing_wallet(asset, wallet, *address_index);
			if (!result || *address_index <= wallet.max_address_index)
				return result;

			auto wallet_copy = wallet;
			wallet_copy.max_address_index = *address_index;

			storages::mediatorstate state = storages::mediatorstate(__func__, asset);
			auto status = state.add_derived_wallet(wallet_copy, *result);
			if (!status)
				return status.error();

			return result;
		}
		expects_lr<mediator::derived_signing_wallet> server_node::new_signing_wallet(const algorithm::asset_id& asset, const secret_box& signing_key)
		{
			if (!algorithm::asset::is_valid(asset))
				return expects_lr<mediator::derived_signing_wallet>(layer_exception("asset not found"));

			if (signing_key.empty())
				return expects_lr<mediator::derived_signing_wallet>(layer_exception("key not found"));

			auto* implementation = get_chain(asset);
			if (!implementation)
				return expects_lr<mediator::derived_signing_wallet>(layer_exception("chain not found"));

			return implementation->new_signing_wallet(asset, signing_key);
		}
		expects_lr<mediator::derived_verifying_wallet> server_node::new_verifying_wallet(const algorithm::asset_id& asset, const std::string_view& verifying_key)
		{
			if (!algorithm::asset::is_valid(asset))
				return expects_lr<mediator::derived_verifying_wallet>(layer_exception("asset not found"));

			if (verifying_key.empty())
				return expects_lr<mediator::derived_verifying_wallet>(layer_exception("key not found"));

			auto* implementation = get_chain(asset);
			if (!implementation)
				return expects_lr<mediator::derived_verifying_wallet>(layer_exception("chain not found"));

			return implementation->new_verifying_wallet(asset, verifying_key);
		}
		expects_lr<string> server_node::new_public_key_hash(const algorithm::asset_id& asset, const std::string_view& address)
		{
			if (!algorithm::asset::is_valid(asset))
				return expects_lr<string>(layer_exception("asset not found"));

			if (address.empty())
				return expects_lr<string>(layer_exception("address not found"));

			auto* implementation = get_chain(asset);
			if (!implementation)
				return expects_lr<string>(layer_exception("chain not found"));

			return implementation->new_public_key_hash(address);
		}
		expects_lr<string> server_node::sign_message(const algorithm::asset_id& asset, const std::string_view& message, const secret_box& signing_key)
		{
			if (!algorithm::asset::is_valid(asset))
				return expects_lr<string>(layer_exception("asset not found"));

			auto* implementation = get_chain(asset);
			if (!implementation)
				return expects_lr<string>(layer_exception("chain not found"));

			return implementation->sign_message(asset, message, signing_key);
		}
		expects_lr<void> server_node::verify_message(const algorithm::asset_id& asset, const std::string_view& message, const std::string_view& verifying_key, const std::string_view& signature)
		{
			if (!algorithm::asset::is_valid(asset))
				return expects_lr<void>(layer_exception("asset not found"));

			auto* implementation = get_chain(asset);
			if (!implementation)
				return expects_lr<void>(layer_exception("chain not found"));

			bool is_message_hex = format::util::is_hex_encoding(message);
			string message_data1 = is_message_hex ? format::util::decode_0xhex(message) : string(message);
			string message_data2 = is_message_hex ? string(message) : format::util::encode_0xhex(message);
			auto status = implementation->verify_message(asset, message_data1, verifying_key, signature);
			if (status)
				return status;

			return implementation->verify_message(asset, message_data2, verifying_key, signature);
		}
		expects_lr<void> server_node::enable_signing_wallet(const algorithm::asset_id& asset, const mediator::master_wallet& wallet, const mediator::derived_signing_wallet& signing_wallet)
		{
			if (!algorithm::asset::is_valid(asset))
				return layer_exception("asset not found");

			if (!wallet.is_valid())
				return layer_exception("wallet not found");

			auto* implementation = get_chain(asset);
			if (!implementation)
				return layer_exception("chain not found");

			if (wallet.max_address_index < signing_wallet.address_index.otherwise(0))
				return layer_exception("bad address index");

			storages::mediatorstate state = storages::mediatorstate(__func__, asset);
			auto status = state.add_derived_wallet(wallet, signing_wallet);
			if (!status)
				return status.error();

			return expectation::met;
		}
		expects_lr<void> server_node::enable_checkpoint_height(const algorithm::asset_id& asset, uint64_t block_height)
		{
			if (!algorithm::asset::is_valid(asset))
				return expects_lr<void>(layer_exception("asset not found"));

			storages::mediatorstate state = storages::mediatorstate(__func__, asset);
			return state.set_property("tip_override", var::set::integer(block_height));
		}
		expects_lr<void> server_node::enable_contract_address(const algorithm::asset_id& asset, const std::string_view& contract_address)
		{
			if (!algorithm::asset::is_valid(asset))
				return expects_lr<void>(layer_exception("asset not found"));

			if (contract_address.empty())
				return expects_lr<void>(layer_exception("contract address not found"));

			auto* implementation = get_chain(asset);
			if (!implementation)
				return expects_lr<void>(layer_exception("chain not found"));

			storages::mediatorstate state = storages::mediatorstate(__func__, asset);
			auto key = "contract_address:" + algorithm::asset::token_of(asset);
			auto value = state.get_property(key);
			if (!value)
				value = var::set::array();

			unordered_set<string> addresses;
			for (auto& item : value->get_childs())
				addresses.insert(item->value.get_blob());

			auto address = implementation->get_checksum_hash(contract_address);
			if (addresses.find(address) != addresses.end())
				return expectation::met;

			value->push(var::set::string(address));
			return state.set_property(key, *value);
		}
		expects_lr<void> server_node::enable_wallet_address(const algorithm::asset_id& asset, const std::string_view& binding, const std::string_view& address, uint64_t address_index)
		{
			if (!algorithm::asset::is_valid(asset))
				return expects_lr<void>(layer_exception("asset not found"));

			if (stringify::is_empty_or_whitespace(address))
				return expects_lr<void>(layer_exception("address not found"));

			if (binding.empty())
				return expects_lr<void>(layer_exception("binding not found"));

			auto* implementation = get_chain(asset);
			if (!implementation)
				return expects_lr<void>(layer_exception("chain not found"));

			storages::mediatorstate state = storages::mediatorstate(__func__, asset);
			string canonical_address = implementation->get_checksum_hash(address);
			auto candidate_address_index = state.get_address_index(canonical_address);
			if (!candidate_address_index)
			{
				mediator::index_address new_address_index;
				new_address_index.binding = binding;
				new_address_index.address = address;
				new_address_index.address_index = address_index;

				auto status = state.set_address_index(canonical_address, new_address_index);
				if (!status)
					return status;
				goto degrade;
			}
			else if (!candidate_address_index->address_index || address_index != *candidate_address_index->address_index)
			{
				candidate_address_index->address_index = address_index;
				auto status = state.set_address_index(canonical_address, *candidate_address_index);
				if (!status)
					return status;
				goto degrade;
			}

			return expectation::met;
		degrade:
			auto block_height = get_latest_known_block_height(asset);
			if (!block_height || !*block_height)
				return expectation::met;

			uint64_t latency = implementation->get_chainparams().sync_latency * protocol::now().user.nss.block_replay_multiplier;
			if (latency > 0)
				enable_checkpoint_height(asset, latency >= *block_height ? 1 : *block_height - latency);

			return expectation::met;
		}
		expects_lr<void> server_node::disable_wallet_address(const algorithm::asset_id& asset, const std::string_view& address)
		{
			if (!algorithm::asset::is_valid(asset))
				return expects_lr<void>(layer_exception("asset not found"));

			if (stringify::is_empty_or_whitespace(address))
				return expects_lr<void>(layer_exception("address not found"));

			auto* implementation = get_chain(asset);
			if (!implementation)
				return expects_lr<void>(layer_exception("chain not found"));

			storages::mediatorstate state = storages::mediatorstate(__func__, asset);
			string canonical_address = implementation->get_checksum_hash(address);
			return state.clear_address_index(canonical_address);
		}
		expects_lr<uint64_t> server_node::get_latest_known_block_height(const algorithm::asset_id& asset)
		{
			if (!algorithm::asset::is_valid(asset))
				return expects_lr<uint64_t>(layer_exception("asset not found"));

			uint64_t block_height = 0;
			storages::mediatorstate state = storages::mediatorstate(__func__, asset);
			auto latest_block_height = uptr<schema>(state.get_property("tip_latest"));
			if (latest_block_height)
			{
				uint64_t possible_block_height = (uint64_t)latest_block_height->value.get_integer();
				if (possible_block_height > block_height)
					block_height = possible_block_height;
			}

			auto checkpoint_block_height = uptr<schema>(state.get_property("tip_checkpoint"));
			if (checkpoint_block_height)
			{
				uint64_t possible_block_height = (uint64_t)checkpoint_block_height->value.get_integer();
				if (possible_block_height > block_height)
					block_height = possible_block_height;
			}

			if (!block_height)
				return expects_lr<uint64_t>(layer_exception("block not found"));

			return expects_lr<uint64_t>(block_height);
		}
		expects_lr<mediator::index_address> server_node::get_address_index(const algorithm::asset_id& asset, const std::string_view& address)
		{
			storages::mediatorstate state = storages::mediatorstate(__func__, asset);
			return state.get_address_index(address);
		}
		expects_lr<unordered_map<string, mediator::index_address>> server_node::get_address_indices(const algorithm::asset_id& asset, const unordered_set<string>& addresses)
		{
			storages::mediatorstate state = storages::mediatorstate(__func__, asset);
			return state.get_address_indices(addresses);
		}
		expects_lr<vector<string>> server_node::get_address_indices(const algorithm::asset_id& asset)
		{
			storages::mediatorstate state = storages::mediatorstate(__func__, asset);
			return state.get_address_indices();
		}
		expects_lr<void> server_node::add_utxo(const algorithm::asset_id& asset, const mediator::index_utxo& value)
		{
			storages::mediatorstate state = storages::mediatorstate(__func__, asset);
			return state.add_utxo(value);
		}
		expects_lr<void> server_node::remove_utxo(const algorithm::asset_id& asset, const std::string_view& transaction_id, uint32_t index)
		{
			storages::mediatorstate state = storages::mediatorstate(__func__, asset);
			return state.remove_utxo(transaction_id, index);
		}
		expects_lr<mediator::index_utxo> server_node::get_utxo(const algorithm::asset_id& asset, const std::string_view& transaction_id, uint32_t index)
		{
			storages::mediatorstate state = storages::mediatorstate(__func__, asset);
			return state.get_utxo(transaction_id, index);
		}
		expects_lr<vector<mediator::index_utxo>> server_node::get_utxos(const algorithm::asset_id& asset, const std::string_view& binding, size_t offset, size_t count)
		{
			storages::mediatorstate state = storages::mediatorstate(__func__, asset);
			return state.get_utxos(binding, offset, count);
		}
		expects_lr<schema*> server_node::load_cache(const algorithm::asset_id& asset, mediator::cache_policy policy, const std::string_view& key)
		{
			storages::mediatorstate state = storages::mediatorstate(__func__, asset);
			return state.get_cache(policy, key);
		}
		expects_lr<void> server_node::store_cache(const algorithm::asset_id& asset, mediator::cache_policy policy, const std::string_view& key, uptr<schema>&& value)
		{
			storages::mediatorstate state = storages::mediatorstate(__func__, asset);
			return state.set_cache(policy, key, std::move(value));
		}
		option<string> server_node::get_contract_address(const algorithm::asset_id& asset)
		{
			if (!algorithm::asset::is_valid(asset))
				return optional::none;

			auto blockchain = algorithm::asset::blockchain_of(asset);
			auto token = algorithm::asset::token_of(asset);
			storages::mediatorstate state = storages::mediatorstate(__func__, asset);
			auto value = uptr<schema>(state.get_property("contract_address:" + token));
			if (!value || value->empty())
				return optional::none;

			auto target_checksum = algorithm::asset::checksum_of(asset);
			for (auto& item : value->get_childs())
			{
				auto candidate_address = item->value.get_blob();
				auto candidate_checksum = algorithm::asset::checksum_of(algorithm::asset::id_of(blockchain, token, candidate_address));
				if (candidate_checksum == target_checksum)
					return candidate_address;
			}

			return value->get(0)->value.get_blob();
		}
		unordered_map<algorithm::asset_id, mediator::relay_backend::chainparams> server_node::get_chains()
		{
			umutex<std::recursive_mutex> unique(control_sys.sync);
			unordered_map<algorithm::asset_id, mediator::relay_backend::chainparams> result;
			result.reserve(chains.size());
			for (auto& next : chains)
				result[algorithm::asset::id_of(next.first)] = next.second->get_chainparams();
			return result;
		}
		unordered_map<string, mediator::master_wallet> server_node::get_wallets(const algorithm::seckey private_key)
		{
			unordered_map<string, mediator::master_wallet> wallets;
			for (auto& chain : get_assets())
			{
				auto wallet = new_master_wallet(chain, private_key);
				if (wallet)
					wallets[algorithm::asset::handle_of(chain)] = std::move(*wallet);
			}
			return wallets;
		}
		unordered_map<string, invocation_callback>& server_node::get_registrations()
		{
			if (!registrations.empty())
				return registrations;

			registrations =
			{
				{ "ARB", chain<mediator::backends::arbitrum>(this) },
				{ "AVAX", chain<mediator::backends::avalanche>(this) },
				{ "BTC", chain<mediator::backends::bitcoin>(this) },
				{ "BCH", chain<mediator::backends::bitcoin_cash>(this) },
				{ "BTG", chain<mediator::backends::bitcoin_gold>(this) },
				{ "BSC", chain<mediator::backends::binance_smart_chain>(this) },
				{ "BSV", chain<mediator::backends::bitcoin_sv>(this) },
				{ "ADA", chain<mediator::backends::cardano>(this) },
				{ "CELO", chain<mediator::backends::celo>(this) },
				{ "DASH", chain<mediator::backends::dash>(this) },
				{ "DGB", chain<mediator::backends::digibyte>(this) },
				{ "DOGE", chain<mediator::backends::dogecoin>(this) },
				{ "ETH", chain<mediator::backends::ethereum>(this) },
				{ "ETC", chain<mediator::backends::ethereum_classic>(this) },
				{ "FTM", chain<mediator::backends::fantom>(this) },
				{ "FUSE", chain<mediator::backends::fuse>(this) },
				{ "ONE", chain<mediator::backends::harmony>(this) },
				{ "LTC", chain<mediator::backends::litecoin>(this) },
				{ "GLMR", chain<mediator::backends::moonbeam>(this) },
				{ "OP", chain<mediator::backends::optimism>(this) },
				{ "MATIC", chain<mediator::backends::polygon>(this) },
				{ "XRP", chain<mediator::backends::ripple>(this) },
				{ "XEC", chain<mediator::backends::ecash>(this) },
				{ "RIF", chain<mediator::backends::rootstock>(this) },
				{ "SOL", chain<mediator::backends::solana>(this) },
				{ "XLM", chain<mediator::backends::stellar>(this) },
				{ "TRX", chain<mediator::backends::tron>(this) },
				{ "ZEC", chain<mediator::backends::zcash>(this) },
				{ "XMR", chain<mediator::backends::monero>(this) },
			};
			return registrations;
		}
		vector<algorithm::asset_id> server_node::get_assets(bool observing_only)
		{
			umutex<std::recursive_mutex> unique(control_sys.sync);
			vector<algorithm::asset_id> currencies;
			if (observing_only)
			{
				currencies.reserve(nodes.size());
				for (auto& node : nodes)
					currencies.push_back(algorithm::asset::id_of(node.first));
			}
			else
			{
				currencies.reserve(chains.size());
				for (auto& next : chains)
					currencies.push_back(algorithm::asset::id_of(next.first));
			}
			return currencies;
		}
		vector<uptr<mediator::server_relay>>* server_node::get_nodes(const algorithm::asset_id& asset)
		{
			umutex<std::recursive_mutex> unique(control_sys.sync);
			auto it = nodes.find(algorithm::asset::blockchain_of(asset));
			if (it == nodes.end() || it->second.empty())
				return nullptr;

			return &it->second;
		}
		const mediator::relay_backend::chainparams* server_node::get_chainparams(const algorithm::asset_id& asset)
		{
			umutex<std::recursive_mutex> unique(control_sys.sync);
			auto it = chains.find(algorithm::asset::blockchain_of(asset));
			if (it != chains.end())
			{
				auto& params = it->second->get_chainparams();
				return &params;
			}

			return nullptr;
		}
		mediator::server_relay* server_node::add_node(const algorithm::asset_id& asset, const std::string_view& URL, double throttling)
		{
			mediator::server_relay* instance = new mediator::server_relay(URL, throttling);
			add_node_instance(asset, instance);
			return instance;
		}
		mediator::server_relay* server_node::get_node(const algorithm::asset_id& asset)
		{
			umutex<std::recursive_mutex> unique(control_sys.sync);
			auto it = nodes.find(algorithm::asset::blockchain_of(asset));
			if (it == nodes.end() || it->second.empty())
				return nullptr;

			if (it->second.size() == 1)
				return *it->second.front();

			size_t index = ((size_t)math<size_t>::random()) % it->second.size();
			return *it->second[index];
		}
		mediator::relay_backend* server_node::get_chain(const algorithm::asset_id& asset)
		{
			umutex<std::recursive_mutex> unique(control_sys.sync);
			auto it = chains.find(algorithm::asset::blockchain_of(asset));
			if (it != chains.end())
				return *it->second;

			return nullptr;
		}
		schema* server_node::add_specifications(const algorithm::asset_id& asset, uptr<schema>&& value)
		{
			umutex<std::recursive_mutex> unique(control_sys.sync);
			auto& instance = specifications[algorithm::asset::blockchain_of(asset)];
			instance = std::move(value);
			return *instance;
		}
		schema* server_node::get_specifications(const algorithm::asset_id& asset)
		{
			umutex<std::recursive_mutex> unique(control_sys.sync);
			auto it = specifications.find(algorithm::asset::blockchain_of(asset));
			if (it != specifications.end())
				return *it->second;

			return nullptr;
		}
		service_control::service_node server_node::get_entrypoint()
		{
			if (!protocol::now().user.nss.server)
				return service_control::service_node();

			service_control::service_node entrypoint;
			entrypoint.startup = std::bind(&server_node::startup, this);
			entrypoint.shutdown = std::bind(&server_node::shutdown, this);
			return entrypoint;
		}
		mediator::multichain_supervisor_options& server_node::get_options()
		{
			return options;
		}
		system_control& server_node::get_control()
		{
			return control_sys;
		}
		void server_node::add_transaction_callback(const std::string_view& name, transaction_callback&& callback)
		{
			umutex<std::recursive_mutex> unique(control_sys.sync);
			if (callback)
				callbacks[string(name)] = std::move(callback);
			else
				callbacks.erase(string(name));
		}
		void server_node::add_node_instance(const algorithm::asset_id& asset, mediator::server_relay* instance)
		{
			umutex<std::recursive_mutex> unique(control_sys.sync);
			nodes[algorithm::asset::blockchain_of(asset)].push_back(instance);
		}
		void server_node::add_chain_instance(const algorithm::asset_id& asset, mediator::relay_backend* instance)
		{
			umutex<std::recursive_mutex> unique(control_sys.sync);
			chains[algorithm::asset::blockchain_of(asset)] = instance;
		}
		void server_node::dispatch_transaction_queue(transaction_queue_state* state, transaction_params* from_params)
		{
			if (!control_sys.enqueue())
				return;

			umutex<std::recursive_mutex> unique(control_sys.sync);
			if (state->is_busy && from_params != nullptr)
			{
				if (protocol::now().user.nss.logging)
					VI_INFO("[observer] %s transaction 0x%p queued (position: %i)", state->blockchain.c_str(), from_params, (int)state->transactions);

				++state->transactions;
				control_sys.dequeue();
				return;
			}
			else if (state->queue.empty())
			{
				if (protocol::now().user.nss.logging)
					VI_INFO("[observer] %s transaction queue emptied (dispatches: %i)", state->blockchain.c_str(), (int)state->transactions);

				state->transactions = 0;
				state->is_busy = false;
				control_sys.dequeue();
				return;
			}
			else if (from_params != nullptr)
				++state->transactions;

			auto* params = state->queue.front();
			state->is_busy = true;
			state->queue.pop();

			if (protocol::now().user.nss.logging)
				VI_INFO("[observer] %s transaction 0x%p now dispatching (position: %i)", state->blockchain.c_str(), params, (int)(state->transactions - state->queue.size() - 1));

			coasync<void>([this, state, params]() -> promise<void>
			{
				auto signed_transaction = coawait(new_transaction(params->asset, params->wallet, params->to, std::move(params->fee)));
				if (!signed_transaction)
				{
					if (protocol::now().user.nss.logging)
						VI_ERR("[observer] %s transaction 0x%p sign failed (%s)", state->blockchain.c_str(), params, signed_transaction.error().what());

					finalize_transaction(state, params, std::move(signed_transaction));
					control_sys.dequeue();
					coreturn_void;
				}

				if (protocol::now().user.nss.logging)
					VI_INFO("[observer] %s transaction 0x%p signed (sighash: %s, data: %s)",
					state->blockchain.c_str(),
					params,
					signed_transaction->transaction.transaction_id.c_str(),
					signed_transaction->data.c_str());

				auto status = coawait(broadcast_transaction(params->asset, params->external_id, *signed_transaction));
				if (!status)
				{
					if (protocol::now().user.nss.logging)
						VI_ERR("[observer] %s transaction 0x%p broadcast failed (%s)", state->blockchain.c_str(), params, status.error().what());

					finalize_transaction(state, params, status.error());
					control_sys.dequeue();
					coreturn_void;
				}
				else if (protocol::now().user.nss.logging)
					VI_INFO("[observer] %s transaction 0x%p broadcasted", state->blockchain.c_str(), params, signed_transaction->transaction.transaction_id.c_str());

				finalize_transaction(state, params, std::move(signed_transaction));
				control_sys.dequeue();
				coreturn_void;
			}, true);
		}
		void server_node::finalize_transaction(transaction_queue_state* state, uptr<transaction_params>&& params, expects_rt<mediator::outgoing_transaction>&& transaction)
		{
			if (protocol::now().user.nss.logging)
				VI_INFO("[observer] %s transaction 0x%p finalized (position: %i)", state->blockchain.c_str(), *params, (int)(state->transactions - state->queue.size() - 1));

			params->future.set(std::move(transaction));
			dispatch_transaction_queue(state, nullptr);
		}
		bool server_node::call_transaction_listener(transaction_listener* listener)
		{
			if (listener->options.is_cancelled(listener->asset) || !control_sys.enqueue())
			{
				listener->is_dead = true;
				return false;
			}
			else if (listener->cooldown_id != INVALID_TASK_ID)
			{
				if (protocol::now().user.nss.logging)
					VI_INFO("[observer] %s server data collection: re-queued", algorithm::asset::handle_of(listener->asset).c_str());
				listener->cooldown_id = INVALID_TASK_ID;
			}
			else if (listener->is_dry_run)
			{
				if (protocol::now().user.nss.logging)
					VI_INFO("[observer] %s server data collection: queued", algorithm::asset::handle_of(listener->asset).c_str());
				listener->is_dry_run = false;
			}
			else if (listener->options.will_wait_for_transactions())
			{
				if (protocol::now().user.nss.logging)
					VI_INFO("[observer] %s server data collection: waiting for updates in %is (total: %is)",
					algorithm::asset::handle_of(listener->asset).c_str(),
					(int)(listener->options.polling_frequency_ms / 1000),
					(int)(listener->options.state.latest_time_awaited / 1000));
				listener->options.state.latest_time_awaited = 0;
			}

			coasync<void>([this, listener]() -> promise<void>
			{
				auto info = coawait(get_transaction_logs(listener->asset, &listener->options));
				if (!info)
				{
					if (info.error().is_retry())
					{
						if (protocol::now().user.nss.logging)
							VI_INFO("[observer] %s server data collection: finalized", algorithm::asset::handle_of(listener->asset).c_str());

						call_transaction_listener(listener);
						control_sys.dequeue();
						coreturn_void;
					}

					umutex<std::recursive_mutex> unique(control_sys.sync);
					if (control_sys.is_active() && !listener->options.is_cancelled(listener->asset))
					{
						listener->cooldown_id = schedule::get()->set_timeout(options.retry_waiting_time_ms, [this, listener]() { call_transaction_listener(listener); });
						if (protocol::now().user.nss.logging)
							VI_ERR("[observer] %s server data collection: waiting for connection (%s)", algorithm::asset::handle_of(listener->asset).c_str(), info.error().what());
					}
					else
						listener->is_dead = true;
					control_sys.dequeue();
					coreturn_void;
				}
				else if (info->transactions.empty())
				{
					if (!info->block_hash.empty())
					{
						if (protocol::now().user.nss.logging)
							VI_INFO("[observer] %s block %s accepted (height: %i, progress: %.2f%%, txns: 0)",
							algorithm::asset::handle_of(listener->asset).c_str(),
							info->block_hash.c_str(),
							(int)info->block_height,
							listener->options.get_checkpoint_percentage());
					}

					for (auto& item : callbacks)
						coawait(item.second(listener->options, std::move(*info)));

					call_transaction_listener(listener);
					control_sys.dequeue();
					coreturn_void;
				}
				else if (protocol::now().user.nss.logging)
					VI_INFO("[observer] %s block %s accepted (height: %i, progress: %.2f%%, txns: %i)",
					algorithm::asset::handle_of(listener->asset).c_str(),
					info->block_hash.c_str(),
					(int)info->block_height,
					listener->options.get_checkpoint_percentage(),
					(int)info->transactions.size());

				if (protocol::now().user.nss.logging)
				{
					for (auto& tx : info->transactions)
					{
						auto chain = get_chain(tx.asset);
						string transfer_logs = stringify::text(
							"%s transaction %s accepted (status: %s, cost: %s %s)\n",
							algorithm::asset::handle_of(listener->asset).c_str(),
							tx.transaction_id.c_str(), tx.is_approved() ? "confirmation" : "pending",
							tx.fee.to_string().c_str(), algorithm::asset::handle_of(tx.asset).c_str());

						if (!tx.is_approved() || (chain && !chain->get_chainparams().sync_latency))
						{
							for (auto& item : tx.from)
							{
								transfer_logs += stringify::text("  <== %s spends %s %s%s%s%s\n",
									item.address.empty() ? "coinbase" : item.address.c_str(), item.value.to_string().c_str(), algorithm::asset::handle_of(tx.asset).c_str(),
									item.address_index ? " (index: " : "", item.address_index ? to_string(*item.address_index).c_str() : "", item.address_index ? ", status: spent)" : "");
							}
							for (auto& item : tx.to)
							{
								transfer_logs += stringify::text("  ==> %s receives %s %s%s%s%s\n",
									item.address.empty() ? "reward" : item.address.c_str(), item.value.to_string().c_str(), algorithm::asset::handle_of(tx.asset).c_str(),
									item.address_index ? " (index: " : "", item.address_index ? to_string(*item.address_index).c_str() : "", item.address_index ? ", status: unspent)" : "");
							}
						}

						if (transfer_logs.back() == '\n')
							transfer_logs.erase(transfer_logs.end() - 1);

						VI_INFO("[observer] %s", transfer_logs.c_str());
					}
				}

				for (auto& item : callbacks)
					coawait(item.second(listener->options, std::move(*info)));

				call_transaction_listener(listener);
				control_sys.dequeue();
				coreturn_void;
			}, true);
			return true;
		}
		void server_node::startup()
		{
			if (!protocol::now().user.nss.server)
				return;
			else if (!options.retry_waiting_time_ms || !control_sys.activate_and_enqueue())
				return;

			if (protocol::now().user.nss.logging)
				VI_INFO("[nss] nss node startup");

			unordered_set<string> blockchains;
			blockchains.reserve(nodes.size());
			for (auto& implementation : nodes)
				blockchains.insert(implementation.first);

			listeners.reserve(blockchains.size());
			for (auto& blockchain : blockchains)
			{
				transaction_listener* listener = memory::init<transaction_listener>();
				listener->asset = algorithm::asset::id_of(blockchain);
				listeners.emplace_back(listener);

				auto& suboptions = *(mediator::supervisor_options*)&listener->options;
				suboptions = *(mediator::supervisor_options*)&options;

				auto it = options.specifics.find(blockchain);
				if (it != options.specifics.end())
					listener->options = it->second;

				if (!call_transaction_listener(listener))
				{
					control_sys.dequeue();
					return shutdown();
				}

				connections.insert(algorithm::asset::blockchain_of(listener->asset));
			}
			control_sys.dequeue();
		}
		void server_node::shutdown()
		{
			if (!control_sys.deactivate())
				return;

			if (protocol::now().user.nss.logging)
				VI_INFO("[nss] nss node shutdown requested");

			umutex<std::recursive_mutex> unique(control_sys.sync);
			for (auto& nodes : nodes)
			{
				for (auto& node : nodes.second)
					node->cancel_activities();
			}

			for (auto& listener : listeners)
			{
				if (schedule::get()->clear_timeout(listener->cooldown_id))
					listener->is_dead = true;
			}

			unique.unlock();
			control_sys.shutdown().wait();
			unique.lock();

			for (auto& nodes : nodes)
			{
				for (auto& node : nodes.second)
					node->allow_activities();
			}
		}
		bool server_node::is_active()
		{
			return control_sys.is_active();
		}
		bool server_node::has_node(const algorithm::asset_id& asset)
		{
			umutex<std::recursive_mutex> unique(control_sys.sync);
			auto target = nodes.find(algorithm::asset::blockchain_of(asset));
			return target != nodes.end();
		}
		bool server_node::has_chain(const algorithm::asset_id& asset)
		{
			umutex<std::recursive_mutex> unique(control_sys.sync);
			auto target = chains.find(algorithm::asset::blockchain_of(asset));
			return target != chains.end();
		}
		bool server_node::has_observer(const algorithm::asset_id& asset)
		{
			return get_chain(asset) != nullptr && get_node(asset) != nullptr;
		}
		bool server_node::has_support(const algorithm::asset_id& asset)
		{
			if (!control_sys.is_active())
				return false;

			auto blockchain = algorithm::asset::blockchain_of(asset);
			umutex<std::recursive_mutex> unique(control_sys.sync);
			return connections.find(blockchain) != connections.end();
		}
	}
}