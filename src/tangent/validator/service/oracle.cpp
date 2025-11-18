#include "oracle.h"
#include "../storage/oraclestate.h"
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
	namespace oracle
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
		static vector<value_transfer> normalize_value(relay_backend* implementation, const vector<value_transfer>& to)
		{
			auto result = to;
			for (auto& next : result)
				next.value = implementation->to_value(next.value);
			return result;
		}
		static computed_fee normalize_value(relay_backend* implementation, const computed_fee& fee)
		{
			auto result = fee;
			result.fee.fee_rate = implementation->to_value(result.fee.fee_rate);
			result.gas.gas_base_price = implementation->to_value(result.gas.gas_base_price);
			result.gas.gas_price = implementation->to_value(result.gas.gas_price);
			return result;
		}
		static decimal normalize_value(relay_backend* implementation, const decimal& value)
		{
			return implementation->to_value(value);
		}

		uptr<schema> computed_wallet::as_schema() const
		{
			auto data = var::set::object();
			data->set("seed", algorithm::encoding::serialize_uint256(seed));
			data->set("secret_key", var::string(format::util::encode_0xhex(std::string_view((char*)secret_key.data(), secret_key.size()))));
			data->set("public_key", var::string(format::util::encode_0xhex(std::string_view((char*)public_key.data(), public_key.size()))));
			data->set("encoded_secret_key", var::string(encoded_secret_key.heap()));
			data->set("encoded_public_key", var::string(encoded_public_key));
			auto* addresses_data = data->set("addresses", var::set::array());
			for (auto encoded_address : encoded_addresses)
			{
				auto intemediate = addresses.find(encoded_address.first);
				auto* address = addresses_data->push(var::set::object());
				address->set("version", var::integer(encoded_address.first));
				address->set("address", intemediate != addresses.end() ? var::string(format::util::encode_0xhex(intemediate->second)) : var::null());
				address->set("encoded_address", var::string(encoded_address.second));
			}
			return data;
		}

		server_node::server_node() noexcept : control_sys("oracle-node")
		{
			auto& chains = get_registrations();
			for (auto& chain : chains)
				chain.second(chain.first);

			auto& config = protocol::now().user.oracle.options;
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
								if (child->value.is(var_type::object))
								{
									unordered_map<string, string> urls;
									for (auto& protocol : child->get_childs())
										urls[protocol->key] = protocol->value.get_blob();
									urls.erase("rps");

									auto rps = child->get_var("rps").get_number();
									if (add_multi_node(asset, std::move(urls), rps) && protocol::now().user.oracle.logging)
										VI_INFO("%s server %i urls added (rps: %.2f)", algorithm::asset::name_of(asset).c_str(), (int)urls.size(), rps);
									else if (protocol::now().user.oracle.logging)
										VI_ERR("failed to add %s server %i urls", algorithm::asset::name_of(asset).c_str(), (int)urls.size());
								}
								else if (child->value.is(var_type::array))
								{
									auto url = child->size() > 0 ? child->get(0)->value.get_string() : child->value.get_string();
									auto rps = child->size() > 1 ? child->get(1)->value.get_number() : 0.0;
									if (add_node(asset, url, rps) && protocol::now().user.oracle.logging)
										VI_INFO("%s server url \"%.*s\" added (rps: %.2f)", algorithm::asset::name_of(asset).c_str(), (int)url.size(), url.data(), rps);
									else if (protocol::now().user.oracle.logging)
										VI_ERR("failed to add %s server url: \"%.*s\"", algorithm::asset::name_of(asset).c_str(), (int)url.size(), url.data());
								}
								else
								{
									auto url = child->value.get_string();
									if (add_node(asset, url, 0.0) && protocol::now().user.oracle.logging)
										VI_INFO("%s server url \"%.*s\" added", algorithm::asset::name_of(asset).c_str(), (int)url.size(), url.data());
									else if (protocol::now().user.oracle.logging)
										VI_ERR("failed to add %s server url: \"%.*s\"", algorithm::asset::name_of(asset).c_str(), (int)url.size(), url.data());
								}
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
							scan_from_block_height(asset, tip->value.get_integer());

						block_confirmations = root->fetch("server.delay");
						if (block_confirmations != nullptr && block_confirmations->value.is(var_type::integer))
							options.add_specific_options(root->key).min_block_confirmations = block_confirmations->value.get_integer();
					}
				}
			}
			if (protocol::now().user.oracle.server && protocol::now().user.oracle.logging)
			{
				auto* output = console::get();
				output->add_colorization("spends", std_color::red);
				output->add_colorization("receives", std_color::green);
				output->add_colorization("pending", std_color::orange);
				output->add_colorization("finalized", std_color::green);
			}
			btc_ecc_start();
		}
		server_node::~server_node() noexcept
		{
			btc_ecc_stop();
		}
		expects_promise_system<http::response_frame> server_node::internal_call(const std::string_view& location, const std::string_view& method, const http::fetch_frame& options)
		{
			if (!control_sys.is_active())
				return expects_promise_system<http::response_frame>(system_exception("http fetch: shutdown", std::make_error_condition(std::errc::network_down)));

			vitex::network::location origin(location);
			if (origin.protocol != "http" && origin.protocol != "https")
				return expects_promise_system<http::response_frame>(system_exception("http fetch: invalid protocol", std::make_error_condition(std::errc::address_family_not_supported)));

			http::request_frame request;
			request.cookies = options.cookies;
			request.headers = options.headers;
			request.content = options.content;
			request.location.assign(origin.path);
			request.set_method(method);
			if (!origin.username.empty() || !origin.password.empty())
				request.set_header("Authorization", http::permissions::authorize(origin.username, origin.password));

			for (auto& item : origin.query)
				request.query += item.first + "=" + item.second + "&";
			if (!request.query.empty())
				request.query.pop_back();

			size_t max_size = options.max_size;
			uint64_t timeout = options.timeout;
			bool secure = origin.protocol == "https";
			string hostname = origin.hostname;
			string port = origin.port > 0 ? to_string(origin.port) : string(secure ? "443" : "80");
			int32_t verify_peers = (secure ? (options.verify_peers >= 0 ? options.verify_peers : PEER_NOT_VERIFIED) : PEER_NOT_SECURE);
			http::client* client = new http::client(timeout);
			add_activity_request(client);
			return dns::get()->lookup_deferred(hostname, port, dns_type::connect, socket_protocol::TCP, socket_type::stream).then<expects_promise_system<http::response_frame>>([this, client, max_size, timeout, verify_peers, request = std::move(request), origin = std::move(origin)](expects_system<socket_address>&& address) mutable -> expects_promise_system<http::response_frame>
			{
				if (!address)
				{
					remove_activity_request(client);
					return expects_promise_system<http::response_frame>(address.error());
				}

				return client->connect_async(*address, verify_peers).then<expects_promise_system<void>>([client, max_size, request = std::move(request)](expects_system<void>&& status) mutable -> expects_promise_system<void>
				{
					if (!status)
						return expects_promise_system<void>(status);

					return client->send_fetch(std::move(request), max_size);
				}).then<expects_promise_system<http::response_frame>>([this, client](expects_system<void>&& status) -> expects_promise_system<http::response_frame>
				{
					if (!status)
					{
						remove_activity_request(client);
						return expects_promise_system<http::response_frame>(status.error());
					}

					auto response = std::move(*client->get_response());
					return client->disconnect().then<expects_system<http::response_frame>>([this, client, response = std::move(response)](expects_system<void>&&) mutable -> expects_system<http::response_frame>
					{
						remove_activity_request(client);
						return std::move(response);
					});
				});
			});
		}
		expects_promise_rt<schema*> server_node::execute_rpc(const algorithm::asset_id& asset, const std::string_view& method, schema_list&& args, cache_policy cache)
		{
			if (!algorithm::asset::is_aux(asset))
				coreturn expects_rt<schema*>(remote_exception("asset not found"));

			if (method.empty())
				coreturn expects_rt<schema*>(remote_exception("method not found"));

			if (!has_node(asset))
				coreturn expects_rt<schema*>(remote_exception("chain not active"));

			auto* implementation = get_chain(asset);
			if (!implementation)
				coreturn expects_rt<schema*>(remote_exception("chain not found"));

			coreturn coawait(implementation->execute_rpc(method, std::move(args), cache));
		}
		expects_promise_rt<uint64_t> server_node::get_latest_block_height(const algorithm::asset_id& asset)
		{
			if (!algorithm::asset::is_aux(asset))
				coreturn expects_rt<uint64_t>(remote_exception("asset not found"));

			if (!has_node(asset))
				coreturn expects_rt<uint64_t>(remote_exception("chain not active"));

			auto* implementation = get_chain(asset);
			if (!implementation)
				coreturn expects_rt<uint64_t>(remote_exception("chain not found"));

			coreturn coawait(implementation->get_latest_block_height());
		}
		expects_promise_rt<schema*> server_node::get_block_transactions(const algorithm::asset_id& asset, uint64_t block_height, string* block_hash)
		{
			if (!algorithm::asset::is_aux(asset))
				coreturn expects_rt<schema*>(remote_exception("asset not found"));

			if (!has_node(asset))
				coreturn expects_rt<schema*>(remote_exception("chain not active"));

			auto* implementation = get_chain(asset);
			if (!implementation)
				coreturn expects_rt<schema*>(remote_exception("chain not found"));

			coreturn coawait(implementation->get_block_transactions(block_height, block_hash));
		}
		expects_promise_rt<transaction_logs> server_node::link_transactions(const algorithm::asset_id& asset, chain_supervisor_options* options)
		{
			if (!algorithm::asset::is_aux(asset))
				coreturn expects_rt<transaction_logs>(remote_exception("asset not found"));

			if (!options)
				coreturn expects_rt<transaction_logs>(remote_exception("options not found"));

			if (!has_node(asset))
				coreturn expects_rt<transaction_logs>(remote_exception("chain not active"));

			auto* implementation = get_chain(asset);
			if (!implementation)
				coreturn expects_rt<transaction_logs>(remote_exception("chain not found"));

			auto* provider = get_node(asset);
			if (!provider)
				coreturn expects_rt<transaction_logs>(remote_exception("node not found"));

			uptr<schema> tip_checkpoint, tip_latest, tip_override;
			bool is_dry_run = !options->has_latest_block_height();
			implementation->interact = [options](server_relay* service) { options->state.interactions.insert(service); };
			options->state.interactions.clear();
			{
				storages::oraclestate state = storages::oraclestate(asset);
				tip_checkpoint = uptr<schema>(state.get_property("TIP:CHECKPOINT"));
				if (tip_checkpoint)
					options->set_checkpoint_from_block((uint64_t)std::max<int64_t>(1, tip_checkpoint->value.get_integer()) - 1);

				tip_latest = uptr<schema>(state.get_property("TIP:LATEST"));
				if (tip_latest && (uint64_t)tip_latest->value.get_integer() > options->state.latest_block_height)
					options->set_checkpoint_from_block((uint64_t)tip_latest->value.get_integer());

				tip_override = uptr<schema>(state.get_property("TIP:OVERRIDE"));
				if (tip_override)
				{
					uint64_t tip = (uint64_t)tip_override->value.get_integer();
					options->state.starting_block_height = tip;
					options->set_checkpoint_from_block(tip);
				}
			}

			if (!options->has_current_block_height())
			{
			retry:
				auto latest_block_height = coawait(implementation->get_latest_block_height());
				if (!latest_block_height)
					coreturn expects_rt<transaction_logs>(std::move(latest_block_height.error()));
				options->set_checkpoint_to_block(*latest_block_height);
				if (is_dry_run && !*latest_block_height)
					is_dry_run = false;
			}

			if (!options->has_next_block_height())
			{
				if (is_dry_run)
					coreturn expects_rt<transaction_logs>(transaction_logs());
				else if (!coawait(provider->yield_for_discovery(options)))
					coreturn expects_rt<transaction_logs>(remote_exception::retry());
				goto retry;
			}

			transaction_logs logs;
			logs.block_height = tip_override ? (uint64_t)tip_override->value.get_integer() : options->get_next_block_height();
			logs.block_hash = to_string(logs.block_height);

			auto transactions = uptr<schema>(coawait(implementation->get_block_transactions(logs.block_height, &logs.block_hash)));
			if (transactions)
			{
				for (auto& item : transactions->get_childs())
				{
					auto computed = coawait(implementation->link_transaction(logs.block_height, logs.block_hash, item));
					if (computed)
						logs.pending.push_back(std::move(*computed));
				}
			}

			storages::oraclestate state = storages::oraclestate(asset);
			if (!tip_checkpoint || (uint64_t)tip_checkpoint->value.get_integer() != logs.block_height)
				state.set_property("TIP:CHECKPOINT", var::set::integer(logs.block_height));
			if (!tip_latest || (uint64_t)tip_latest->value.get_integer() != options->state.latest_block_height)
				state.set_property("TIP:LATEST", var::set::integer(options->state.latest_block_height));
			if (tip_override)
				state.set_property("TIP:OVERRIDE", nullptr);

			auto* utxo_implementation = relay_backend_utxo::from_relay(implementation);
			auto* server = server_node::get();
			unordered_set<string> transaction_ids;
			for (auto& new_transaction : logs.pending)
			{
				new_transaction.block_id = logs.block_height;
				server->normalize_transaction_id(asset, &new_transaction.transaction_id);
				state.add_incoming_transaction(new_transaction, false);
				transaction_ids.insert(algorithm::asset::handle_of(asset) + ":" + new_transaction.transaction_id);
				if (utxo_implementation != nullptr)
					utxo_implementation->update_utxo(new_transaction);
			}

			auto approvals = state.finalize_computed_transactions(logs.block_height, implementation->get_chainparams().sync_latency);
			if (approvals)
				logs.finalized = std::move(*approvals);

			coreturn expects_rt<transaction_logs>(std::move(logs));
		}
		expects_promise_rt<computed_transaction> server_node::link_transaction(const algorithm::asset_id& asset, uint64_t block_height, const std::string_view& block_hash, schema* transaction_data)
		{
			if (!algorithm::asset::is_aux(asset))
				coreturn expects_rt<computed_transaction>(remote_exception("asset not found"));

			if (!block_height)
				coreturn expects_rt<computed_transaction>(remote_exception("txs not found"));

			if (!has_node(asset))
				coreturn expects_rt<computed_transaction>(remote_exception("chain not active"));

			auto* implementation = get_chain(asset);
			if (!implementation)
				coreturn expects_rt<computed_transaction>(remote_exception("chain not found"));

			coreturn coawait(implementation->link_transaction(block_height, block_hash, transaction_data));
		}
		expects_promise_rt<decimal> server_node::calculate_balance(const algorithm::asset_id& asset, const wallet_link& link)
		{
			if (!algorithm::asset::is_aux(asset))
				coreturn expects_rt<decimal>(remote_exception("asset not found"));

			auto normalized_link = normalize_link(asset, link);
			if (!normalized_link)
				coreturn expects_rt<decimal>(remote_exception(std::move(normalized_link.error().message())));

			if (!has_node(asset))
				coreturn expects_rt<decimal>(remote_exception("chain not active"));

			auto* implementation = get_chain(asset);
			if (!implementation)
				coreturn expects_rt<decimal>(remote_exception("chain not found"));

			coreturn coawait(implementation->calculate_balance(asset, *normalized_link));
		}
		expects_promise_rt<void> server_node::broadcast_transaction(const algorithm::asset_id& asset, const uint256_t& external_id, const finalized_transaction& finalized)
		{
			if (!algorithm::asset::is_aux(asset))
				coreturn expects_rt<void>(remote_exception("asset not found"));

			if (!finalized.is_valid())
				coreturn expects_rt<void>(remote_exception("transaction is not valid"));

			if (!has_node(asset))
				coreturn expects_rt<void>(remote_exception("chain not active"));

			auto* implementation = get_chain(asset);
			if (!implementation)
				coreturn expects_rt<void>(remote_exception("chain not found"));

			auto* server = server_node::get();
			auto new_transaction = finalized.as_computed();
			server->normalize_transaction_id(asset, &new_transaction.transaction_id);
			new_transaction.block_id = 0;
			{
				storages::oraclestate state = storages::oraclestate(asset);
				auto duplicate_transaction = state.get_computed_transaction(new_transaction.transaction_id, external_id, algorithm::hashing::hash256i(new_transaction.transaction_id));
				if (duplicate_transaction)
					coreturn expects_rt<void>(expectation::met);

				auto status = state.add_outgoing_transaction(new_transaction, external_id);
				if (!status)
					coreturn expects_rt<void>(remote_exception(std::move(status.error().message())));
			}

			auto result = coawait(implementation->broadcast_transaction(finalized));
			if (!result)
				coreturn result;

			auto* utxo_implementation = relay_backend_utxo::from_relay(implementation);
			if (utxo_implementation != nullptr)
				utxo_implementation->update_utxo(finalized.prepared);

			coreturn result;
		}
		expects_promise_rt<prepared_transaction> server_node::prepare_transaction(const algorithm::asset_id& asset, const wallet_link& from_link, const vector<value_transfer>& to, const decimal& max_fee)
		{
			if (!algorithm::asset::is_aux(asset))
				coreturn expects_rt<prepared_transaction>(remote_exception("asset not found"));

			if (!has_node(asset))
				coreturn expects_rt<prepared_transaction>(remote_exception("chain not active"));

			auto* implementation = get_chain(asset);
			if (!implementation)
				coreturn expects_rt<prepared_transaction>(remote_exception("chain not found"));

			auto normalized_to = normalize_value(implementation, to);
			if (normalized_to.empty())
				coreturn expects_rt<prepared_transaction>(remote_exception("to address not found"));

			auto blockchain = algorithm::asset::blockchain_of(asset);
			for (auto& next : normalized_to)
			{
				if (!next.is_valid())
					coreturn expects_rt<prepared_transaction>(remote_exception("receiver address not valid"));

				if (!algorithm::asset::is_aux(next.asset) || algorithm::asset::blockchain_of(next.asset) != blockchain)
					coreturn expects_rt<prepared_transaction>(remote_exception("receiver asset not valid"));
			}

			auto normalized_from_link = normalize_link(asset, from_link);
			if (!normalized_from_link)
				coreturn expects_rt<prepared_transaction>(remote_exception(std::move(normalized_from_link.error().message())));

			if (!implementation->get_chainparams().supports_bulk_transfer && normalized_to.size() > 1)
				coreturn expects_rt<prepared_transaction>(remote_exception("only one receiver allowed"));

			auto normalized_max_fee = normalize_value(implementation, max_fee);
			coreturn coawait(implementation->prepare_transaction(*normalized_from_link, normalized_to, normalized_max_fee));
		}
		expects_lr<finalized_transaction> server_node::finalize_transaction(const algorithm::asset_id& asset, prepared_transaction&& prepared)
		{
			if (!algorithm::asset::is_aux(asset))
				return layer_exception("asset not found");

			auto status = prepared.as_status();
			if (status != prepared_transaction::status::requires_finalization)
				return layer_exception(status == prepared_transaction::status::invalid ? "transaction is not valid for finalization" : "transaction does not require finalization");

			auto* implementation = get_chain(asset);
			if (!implementation)
				return layer_exception("chain not found");

			auto blockchain = algorithm::asset::blockchain_of(asset);
			auto base_asset = algorithm::asset::base_id_of(asset);
			for (auto& [hash, input] : prepared.inputs)
			{
				auto input_asset = input.utxo.get_asset(base_asset);
				if (!algorithm::asset::is_aux(input_asset) || algorithm::asset::blockchain_of(input_asset) != blockchain)
					return layer_exception("input asset not valid");

				for (auto& [input_token_hash, input_token] : input.utxo.tokens)
				{
					if (!algorithm::asset::is_aux(input_token.get_asset(base_asset)))
						return layer_exception("invalid input token asset");
				}
			}

			for (auto& [hash, output] : prepared.outputs)
			{
				auto output_asset = output.get_asset(base_asset);
				if (!algorithm::asset::is_aux(output_asset) || algorithm::asset::blockchain_of(output_asset) != blockchain)
					return layer_exception("invalid output asset");

				for (auto& [output_token_hash, output_token] : output.tokens)
				{
					if (!algorithm::asset::is_aux(output_token.get_asset(base_asset)))
						return layer_exception("invalid output token asset");
				}
			}

			return implementation->finalize_transaction(std::move(prepared));
		}
		expects_lr<computed_transaction> server_node::get_computed_transaction(const algorithm::asset_id& asset, const std::string_view& transaction_id, const uint256_t& external_id, const uint256_t& optimized_id)
		{
			if (!algorithm::asset::is_aux(asset))
				return layer_exception("asset not found");

			storages::oraclestate state = storages::oraclestate(asset);
			return state.get_computed_transaction(transaction_id, external_id, optimized_id);
		}
		expects_lr<computed_wallet> server_node::compute_wallet(const algorithm::asset_id& asset, const uint256_t& seed)
		{
			if (!algorithm::asset::is_aux(asset))
				return expects_lr<computed_wallet>(layer_exception("asset not found"));

			auto* implementation = get_chain(asset);
			if (!implementation)
				return expects_lr<computed_wallet>(layer_exception("chain not found"));

			auto& chain = implementation->get_chainparams();
			auto keypair = algorithm::composition::derive_keypair(chain.composition, seed);
			if (!keypair)
				return keypair.error();

			computed_wallet wallet;
			wallet.seed = seed;
			wallet.secret_key = std::move(keypair->secret_key);
			wallet.public_key = std::move(keypair->public_key);
			wallet.encoded_seed = secret_box::secure(algorithm::encoding::encode_0xhex256(seed));

			auto encoded_secret_key = implementation->encode_secret_key(secret_box::view(std::string_view((char*)wallet.secret_key.data(), wallet.secret_key.size())));
			if (!encoded_secret_key)
				return encoded_secret_key.error();

			auto encoded_public_key = implementation->encode_public_key(std::string_view((char*)wallet.public_key.data(), wallet.public_key.size()));
			if (!encoded_public_key)
				return encoded_public_key.error();

			auto encoded_addresses = implementation->to_addresses(*encoded_public_key);
			if (!encoded_addresses)
				return encoded_addresses.error();

			wallet.encoded_secret_key = std::move(*encoded_secret_key);
			wallet.encoded_public_key = std::move(*encoded_public_key);
			wallet.encoded_addresses = std::move(*encoded_addresses);
			for (auto& [index, address] : wallet.encoded_addresses)
			{
				auto decoded_address = implementation->decode_address(address);
				if (!decoded_address)
					return decoded_address.error();

				wallet.addresses[index] = std::move(*decoded_address);
			}

			return expects_lr<computed_wallet>(std::move(wallet));
		}
		expects_lr<secret_box> server_node::encode_secret_key(const algorithm::asset_id& asset, const secret_box& secret_key)
		{
			if (!algorithm::asset::is_aux(asset))
				return expects_lr<secret_box>(layer_exception("asset not found"));

			if (secret_key.empty())
				return expects_lr<secret_box>(layer_exception("secret key not found"));

			auto* implementation = get_chain(asset);
			if (!implementation)
				return expects_lr<secret_box>(layer_exception("chain not found"));

			return implementation->encode_secret_key(secret_key);
		}
		expects_lr<secret_box> server_node::decode_secret_key(const algorithm::asset_id& asset, const secret_box& secret_key)
		{
			if (!algorithm::asset::is_aux(asset))
				return expects_lr<secret_box>(layer_exception("asset not found"));

			if (secret_key.empty())
				return expects_lr<secret_box>(layer_exception("secret key not found"));

			auto* implementation = get_chain(asset);
			if (!implementation)
				return expects_lr<secret_box>(layer_exception("chain not found"));

			return implementation->decode_secret_key(secret_key);
		}
		expects_lr<string> server_node::encode_public_key(const algorithm::asset_id& asset, const std::string_view& public_key)
		{
			if (!algorithm::asset::is_aux(asset))
				return expects_lr<string>(layer_exception("asset not found"));

			if (public_key.empty())
				return expects_lr<string>(layer_exception("public key not found"));

			auto* implementation = get_chain(asset);
			if (!implementation)
				return expects_lr<string>(layer_exception("chain not found"));

			return implementation->encode_public_key(public_key);
		}
		expects_lr<string> server_node::decode_public_key(const algorithm::asset_id& asset, const std::string_view& public_key)
		{
			if (!algorithm::asset::is_aux(asset))
				return expects_lr<string>(layer_exception("asset not found"));

			if (stringify::is_empty_or_whitespace(public_key))
				return expects_lr<string>(layer_exception("public key not found"));

			auto* implementation = get_chain(asset);
			if (!implementation)
				return expects_lr<string>(layer_exception("chain not found"));

			return implementation->decode_public_key(public_key);
		}
		expects_lr<string> server_node::encode_address(const algorithm::asset_id& asset, const std::string_view& public_key_hash)
		{
			if (!algorithm::asset::is_aux(asset))
				return expects_lr<string>(layer_exception("asset not found"));

			if (public_key_hash.empty())
				return expects_lr<string>(layer_exception("public key hash not found"));

			auto* implementation = get_chain(asset);
			if (!implementation)
				return expects_lr<string>(layer_exception("chain not found"));

			return implementation->encode_address(public_key_hash);
		}
		expects_lr<string> server_node::decode_address(const algorithm::asset_id& asset, const std::string_view& address)
		{
			if (!algorithm::asset::is_aux(asset))
				return expects_lr<string>(layer_exception("asset not found"));

			if (stringify::is_empty_or_whitespace(address))
				return expects_lr<string>(layer_exception("address not found"));
			
			auto* implementation = get_chain(asset);
			if (!implementation)
				return expects_lr<string>(layer_exception("chain not found"));

			return implementation->decode_address(address);
		}
		expects_lr<string> server_node::encode_transaction_id(const algorithm::asset_id& asset, const std::string_view& transaction_id)
		{
			if (!algorithm::asset::is_aux(asset))
				return expects_lr<string>(layer_exception("asset not found"));

			if (transaction_id.empty())
				return expects_lr<string>(layer_exception("transaction id not found"));

			auto* implementation = get_chain(asset);
			if (!implementation)
				return expects_lr<string>(layer_exception("chain not found"));

			return implementation->encode_transaction_id(transaction_id);
		}
		expects_lr<string> server_node::decode_transaction_id(const algorithm::asset_id& asset, const std::string_view& transaction_id)
		{
			if (!algorithm::asset::is_aux(asset))
				return expects_lr<string>(layer_exception("asset not found"));

			if (stringify::is_empty_or_whitespace(transaction_id))
				return expects_lr<string>(layer_exception("transaction id not found"));

			auto* implementation = get_chain(asset);
			if (!implementation)
				return expects_lr<string>(layer_exception("chain not found"));

			return implementation->decode_transaction_id(transaction_id);
		}
		expects_lr<void> server_node::normalize_secret_key(const algorithm::asset_id& asset, secret_box* secret_key)
		{
			VI_ASSERT(secret_key != nullptr, "secret key should be set");
			auto decoded = decode_secret_key(asset, *secret_key);
			if (!decoded)
				return decoded.error();

			auto encoded = encode_secret_key(asset, *decoded);
			if (!encoded)
				return encoded.error();

			*secret_key = std::move(*encoded);
			return expectation::met;
		}
		expects_lr<void> server_node::normalize_public_key(const algorithm::asset_id& asset, string* public_key)
		{
			VI_ASSERT(public_key != nullptr, "public key should be set");
			auto decoded = decode_public_key(asset, *public_key);
			if (!decoded)
				return decoded.error();

			auto encoded = encode_public_key(asset, *decoded);
			if (!encoded)
				return encoded.error();

			*public_key = std::move(*encoded);
			return expectation::met;
		}
		expects_lr<void> server_node::normalize_address(const algorithm::asset_id& asset, string* address)
		{
			VI_ASSERT(address != nullptr, "address should be set");
			auto decoded = decode_address(asset, *address);
			if (!decoded)
				return decoded.error();

			auto encoded = encode_address(asset, *decoded);
			if (!encoded)
				return encoded.error();

			*address = std::move(*encoded);
			return expectation::met;
		}
		expects_lr<void> server_node::normalize_transaction_id(const algorithm::asset_id& asset, string* transaction_id)
		{
			VI_ASSERT(transaction_id != nullptr, "transaction id should be set");
			auto decoded = decode_transaction_id(asset, *transaction_id);
			if (!decoded)
				return decoded.error();

			auto encoded = encode_transaction_id(asset, *decoded);
			if (!encoded)
				return encoded.error();

			*transaction_id = std::move(*encoded);
			return expectation::met;
		}
		expects_lr<algorithm::composition::cpubkey_t> server_node::to_composite_public_key(const algorithm::asset_id& asset, const std::string_view& public_key)
		{
			if (!algorithm::asset::is_aux(asset))
				return expects_lr<algorithm::composition::cpubkey_t>(layer_exception("asset not found"));

			if (public_key.empty())
				return expects_lr<algorithm::composition::cpubkey_t>(layer_exception("public key not found"));

			auto* implementation = get_chain(asset);
			if (!implementation)
				return expects_lr<algorithm::composition::cpubkey_t>(layer_exception("chain not found"));

			return implementation->to_composite_public_key(public_key);
		}
		expects_lr<address_map> server_node::to_addresses(const algorithm::asset_id& asset, const std::string_view& public_key)
		{
			if (!algorithm::asset::is_aux(asset))
				return expects_lr<address_map>(layer_exception("asset not found"));

			if (public_key.empty())
				return expects_lr<address_map>(layer_exception("public key not found"));

			auto* implementation = get_chain(asset);
			if (!implementation)
				return expects_lr<address_map>(layer_exception("chain not found"));

			return implementation->to_addresses(public_key);
		}
		expects_lr<void> server_node::scan_from_block_height(const algorithm::asset_id& asset, uint64_t block_height)
		{
			if (!algorithm::asset::is_aux(asset))
				return expects_lr<void>(layer_exception("asset not found"));

			storages::oraclestate state = storages::oraclestate(asset);
			return state.set_property("TIP:OVERRIDE", var::set::integer(block_height));
		}
		expects_lr<void> server_node::trigger_node_activity(const algorithm::asset_id& asset)
		{
			umutex<std::recursive_mutex> unique(control_sys.sync);
			auto it = nodes.find(algorithm::asset::blockchain_of(asset));
			if (it == nodes.end() || it->second.empty())
				return layer_exception("trigger not possible");

			for (auto& node : it->second)
				node->trigger_activities();

			return expectation::met;
		}
		expects_lr<void> server_node::enable_contract_address(const algorithm::asset_id& asset, const std::string_view& contract_address)
		{
			if (!algorithm::asset::is_aux(asset))
				return expects_lr<void>(layer_exception("asset not found"));

			if (contract_address.empty())
				return expects_lr<void>(layer_exception("contract address not found"));

			auto* implementation = get_chain(asset);
			if (!implementation)
				return expects_lr<void>(layer_exception("chain not found"));

			storages::oraclestate state = storages::oraclestate(asset);
			auto key = algorithm::asset::token_of(asset);
			auto value = state.get_property(key);
			if (!value)
				value = var::set::array();

			unordered_set<string> addresses;
			for (auto& item : value->get_childs())
				addresses.insert(item->value.get_blob());

			auto address = string(contract_address);
			normalize_address(asset, &address);
			if (addresses.find(address) != addresses.end())
				return expectation::met;

			value->push(var::set::string(address));
			return state.set_property(key, *value);
		}
		expects_lr<void> server_node::enable_link(const algorithm::asset_id& asset, const wallet_link& link)
		{
			if (!algorithm::asset::is_aux(asset))
				return expects_lr<void>(layer_exception("asset not found"));

			if (!link.has_all())
				return expects_lr<void>(layer_exception("link not found"));

			auto* implementation = get_chain(asset);
			if (!implementation)
				return expects_lr<void>(layer_exception("chain not found"));

			auto copy = link;
			auto status = normalize_public_key(asset, &copy.public_key);
			if (!status)
				return status;

			status = normalize_address(asset, &copy.address);
			if (!status)
				return status;

			storages::oraclestate state = storages::oraclestate(asset);
			auto candidate_link = state.get_link(copy.address);
			if (candidate_link && candidate_link->as_hash() == copy.as_hash())
				return expectation::met;

			status = state.set_link(copy);
			if (!status)
				return status;

			auto block_height = get_latest_known_block_height(asset);
			if (!block_height || !*block_height)
				return expectation::met;

			uint64_t latency = implementation->get_chainparams().sync_latency * protocol::now().user.oracle.block_replay_multiplier;
			if (latency > 0)
				scan_from_block_height(asset, latency >= *block_height ? 1 : *block_height - latency);

			return expectation::met;
		}
		expects_lr<void> server_node::disable_link(const algorithm::asset_id& asset, const wallet_link& link)
		{
			if (!algorithm::asset::is_aux(asset))
				return expects_lr<void>(layer_exception("asset not found"));

			if (!link.has_all())
				return expects_lr<void>(layer_exception("address not found"));

			auto* implementation = get_chain(asset);
			if (!implementation)
				return expects_lr<void>(layer_exception("chain not found"));

			auto copy = link;
			auto status = normalize_public_key(asset, &copy.public_key);
			if (!status)
				return status;

			status = normalize_address(asset, &copy.address);
			if (!status)
				return status;

			storages::oraclestate state = storages::oraclestate(asset);
			return state.clear_link(copy);
		}
		expects_lr<wallet_link> server_node::normalize_link(const algorithm::asset_id& asset, const wallet_link& link)
		{
			if (link.has_address())
			{
				auto result = get_links_by_addresses(asset, { link.address });
				if (result && !result->empty())
					return expects_lr<wallet_link>(std::move(result->begin()->second));
			}

			if (link.has_public_key())
			{
				auto result = get_links_by_public_keys(asset, { link.public_key });
				if (result && !result->empty())
					return expects_lr<wallet_link>(std::move(result->begin()->second));
			}

			if (link.has_owner())
			{
				auto result = get_links_by_owner(asset, link.owner, 0, 1);
				if (result && !result->empty())
					return expects_lr<wallet_link>(std::move(result->begin()->second));
			}

			return layer_exception("link not found");
		}
		expects_lr<uint64_t> server_node::get_latest_known_block_height(const algorithm::asset_id& asset)
		{
			if (!algorithm::asset::is_aux(asset))
				return expects_lr<uint64_t>(layer_exception("asset not found"));

			uint64_t block_height = 0;
			storages::oraclestate state = storages::oraclestate(asset);
			auto latest_block_height = uptr<schema>(state.get_property("TIP:LATEST"));
			if (latest_block_height)
			{
				uint64_t possible_block_height = (uint64_t)latest_block_height->value.get_integer();
				if (possible_block_height > block_height)
					block_height = possible_block_height;
			}

			auto checkpoint_block_height = uptr<schema>(state.get_property("TIP:CHECKPOINT"));
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
		expects_lr<wallet_link> server_node::get_link(const algorithm::asset_id& asset, const std::string_view& address)
		{
			storages::oraclestate state = storages::oraclestate(asset);
			return state.get_link(address);
		}
		expects_lr<unordered_map<string, wallet_link>> server_node::get_links_by_owner(const algorithm::asset_id& asset, const algorithm::pubkeyhash_t& owner, size_t offset, size_t count)
		{
			storages::oraclestate state = storages::oraclestate(asset);
			return state.get_links_by_owner(owner, offset, count);
		}
		expects_lr<unordered_map<string, wallet_link>> server_node::get_links_by_public_keys(const algorithm::asset_id& asset, const unordered_set<string>& public_keys)
		{
			storages::oraclestate state = storages::oraclestate(asset);
			return state.get_links_by_public_keys(public_keys);
		}
		expects_lr<unordered_map<string, wallet_link>> server_node::get_links_by_addresses(const algorithm::asset_id& asset, const unordered_set<string>& addresses)
		{
			storages::oraclestate state = storages::oraclestate(asset);
			return state.get_links_by_addresses(addresses);
		}
		expects_lr<void> server_node::add_utxo(const algorithm::asset_id& asset, const coin_utxo& value)
		{
			storages::oraclestate state = storages::oraclestate(asset);
			return state.add_utxo(value);
		}
		expects_lr<void> server_node::remove_utxo(const algorithm::asset_id& asset, const std::string_view& transaction_id, uint64_t index)
		{
			storages::oraclestate state = storages::oraclestate(asset);
			return state.remove_utxo(transaction_id, index);
		}
		expects_lr<coin_utxo> server_node::get_utxo(const algorithm::asset_id& asset, const std::string_view& transaction_id, uint64_t index)
		{
			storages::oraclestate state = storages::oraclestate(asset);
			return state.get_utxo(transaction_id, index);
		}
		expects_lr<vector<coin_utxo>> server_node::get_utxos(const algorithm::asset_id& asset, const wallet_link& link, size_t offset, size_t count)
		{
			storages::oraclestate state = storages::oraclestate(asset);
			return state.get_utxos(link, offset, count);
		}
		expects_lr<schema*> server_node::load_cache(const algorithm::asset_id& asset, cache_policy policy, const std::string_view& key)
		{
			storages::oraclestate state = storages::oraclestate(asset);
			return state.get_cache(policy, key);
		}
		expects_lr<void> server_node::store_cache(const algorithm::asset_id& asset, cache_policy policy, const std::string_view& key, uptr<schema>&& value)
		{
			storages::oraclestate state = storages::oraclestate(asset);
			return state.set_cache(policy, key, std::move(value));
		}
		option<string> server_node::get_contract_address(const algorithm::asset_id& asset)
		{
			if (!algorithm::asset::is_aux(asset))
				return optional::none;

			auto blockchain = algorithm::asset::blockchain_of(asset);
			auto token = algorithm::asset::token_of(asset);
			storages::oraclestate state = storages::oraclestate(asset);
			auto value = uptr<schema>(state.get_property(token));
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
		unordered_map<algorithm::asset_id, relay_backend::chainparams> server_node::get_chains()
		{
			umutex<std::recursive_mutex> unique(control_sys.sync);
			unordered_map<algorithm::asset_id, relay_backend::chainparams> result;
			result.reserve(chains.size());
			for (auto& next : chains)
				result[algorithm::asset::id_of(next.first)] = next.second->get_chainparams();
			return result;
		}
		unordered_map<string, invocation_callback>& server_node::get_registrations()
		{
			if (!registrations.empty())
				return registrations;

			registrations =
			{
				{ "ADA", chain<backends::cardano>(this) },
				{ "BTC", chain<backends::bitcoin>(this) },
				{ "ETH", chain<backends::ethereum>(this) },
				{ "SOL", chain<backends::solana>(this) },
				{ "TRX", chain<backends::tron>(this) },
				{ "XRP", chain<backends::ripple>(this) },
				{ "XLM", chain<backends::stellar>(this) },
#if 0
				{ "BCH", chain<backends::forks::bitcoin_cash>(this) },
				{ "BTG", chain<backends::forks::bitcoin_gold>(this) },
				{ "BSV", chain<backends::forks::bitcoin_sv>(this) },
				{ "DASH", chain<backends::forks::dash>(this) },
				{ "DGB", chain<backends::forks::digibyte>(this) },
				{ "DOGE", chain<backends::forks::dogecoin>(this) },
				{ "LTC", chain<backends::forks::litecoin>(this) },
				{ "XEC", chain<backends::forks::ecash>(this) },
				{ "ZEC", chain<backends::forks::zcash>(this) },
				{ "ARB", chain<backends::forks::arbitrum>(this) },
				{ "AVAX", chain<backends::forks::avalanche>(this) },
				{ "BASE", chain<backends::forks::base>(this) },
				{ "BLAST", chain<backends::forks::blast>(this) },
				{ "BNB", chain<backends::forks::bnb>(this) },
				{ "CELO", chain<backends::forks::celo>(this) },
				{ "ETC", chain<backends::forks::ethereum_classic>(this) },
				{ "GNO", chain<backends::forks::gnosis>(this) },
				{ "LINEA", chain<backends::forks::linea>(this) },
				{ "MATIC", chain<backends::forks::polygon>(this) },
				{ "OP", chain<backends::forks::optimism>(this) },
				{ "S", chain<backends::forks::sonic>(this) },
				{ "ZK", chain<backends::forks::zksync>(this) },
				{ "XMR", chain<backends::monero>(this) },
#endif
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
		vector<uptr<server_relay>>* server_node::get_nodes(const algorithm::asset_id& asset)
		{
			umutex<std::recursive_mutex> unique(control_sys.sync);
			auto it = nodes.find(algorithm::asset::blockchain_of(asset));
			if (it == nodes.end() || it->second.empty())
				return nullptr;

			return &it->second;
		}
		const relay_backend::chainparams* server_node::get_chainparams(const algorithm::asset_id& asset)
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
		server_relay* server_node::add_node(const algorithm::asset_id& asset, const std::string_view& url, double rps)
		{
			server_relay* instance = new server_relay({ { "auto", string(url) } }, rps);
			add_node_instance(asset, instance);
			return instance;
		}
		server_relay* server_node::add_multi_node(const algorithm::asset_id& asset, unordered_map<string, string>&& urls, double rps)
		{
			server_relay* instance = new server_relay(std::move(urls), rps);
			add_node_instance(asset, instance);
			return instance;
		}
		server_relay* server_node::get_node(const algorithm::asset_id& asset)
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
		relay_backend* server_node::get_chain(const algorithm::asset_id& asset)
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
			if (value)
			{
				auto& instance = specifications[algorithm::asset::blockchain_of(asset)];
				instance = std::move(value);
				return *instance;
			}
			else
			{
				specifications.erase(algorithm::asset::blockchain_of(asset));
				return nullptr;
			}
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
			if (!protocol::now().user.oracle.server)
				return service_control::service_node();

			service_control::service_node entrypoint;
			entrypoint.startup = std::bind(&server_node::startup, this);
			entrypoint.shutdown = std::bind(&server_node::shutdown, this);
			return entrypoint;
		}
		multichain_supervisor_options& server_node::get_options()
		{
			return options;
		}
		system_control& server_node::get_control()
		{
			return control_sys;
		}
		void server_node::remove_chain(const algorithm::asset_id& asset)
		{
			umutex<std::recursive_mutex> unique(control_sys.sync);
			auto it = nodes.find(algorithm::asset::blockchain_of(asset));
			if (it != nodes.end())
			{
				for (auto& node : it->second)
					node->cancel_activities();
				nodes.erase(it);
			}
		}
		void server_node::remove_nodes(const algorithm::asset_id& asset)
		{
			umutex<std::recursive_mutex> unique(control_sys.sync);
			chains.erase(algorithm::asset::blockchain_of(asset));
		}
		void server_node::add_activity_listener(transaction_listener* listener)
		{
			umutex<std::mutex> unique(activity.mutex);
			++activity.listeners[listener];
		}
		void server_node::remove_activity_listener(transaction_listener* listener)
		{
			umutex<std::mutex> unique(activity.mutex);
			auto& index = activity.listeners[listener];
			if (index == 1)
				activity.listeners.erase(listener);
			else
				--index;
		}
		void server_node::add_activity_request(http::client* client)
		{
			umutex<std::mutex> unique(activity.mutex);
			activity.requests.insert(client);
		}
		void server_node::remove_activity_request(http::client* client)
		{
			umutex<std::mutex> unique(activity.mutex);
			activity.requests.erase(client);
			client->release();
		}
		void server_node::add_transaction_callback(const std::string_view& name, transaction_callback&& callback)
		{
			umutex<std::recursive_mutex> unique(control_sys.sync);
			if (callback)
				callbacks[string(name)] = std::move(callback);
			else
				callbacks.erase(string(name));
		}
		void server_node::add_node_instance(const algorithm::asset_id& asset, server_relay* instance)
		{
			umutex<std::recursive_mutex> unique(control_sys.sync);
			nodes[algorithm::asset::blockchain_of(asset)].push_back(instance);
		}
		void server_node::add_chain_instance(const algorithm::asset_id& asset, relay_backend* instance)
		{
			umutex<std::recursive_mutex> unique(control_sys.sync);
			chains[algorithm::asset::blockchain_of(asset)] = instance;
		}
		bool server_node::call_transaction_listener(transaction_listener* listener)
		{
			if (listener->options.is_cancelled(listener->asset) || !control_sys.is_active())
			{
				listener->is_dead = true;
				return false;
			}
			else if (listener->cooldown_id != INVALID_TASK_ID)
			{
				if (protocol::now().user.oracle.logging)
					VI_INFO("%s server data collection: re-queued", algorithm::asset::name_of(listener->asset).c_str());
				listener->cooldown_id = INVALID_TASK_ID;
			}
			else if (listener->is_dry_run)
			{
				if (protocol::now().user.oracle.logging)
					VI_INFO("%s server data collection: queued", algorithm::asset::name_of(listener->asset).c_str());
				listener->is_dry_run = false;
			}
			else if (listener->options.will_wait_for_transactions())
			{
				if (protocol::now().user.oracle.logging)
					VI_INFO("%s server data collection: waiting for updates in %is (total: %is)",
					algorithm::asset::name_of(listener->asset).c_str(),
					(int)(listener->options.polling_frequency_ms / 1000),
					(int)(listener->options.state.latest_time_awaited / 1000));
				listener->options.state.latest_time_awaited = 0;
			}

			add_activity_listener(listener);
			coasync<void>([this, listener]() -> promise<void>
			{
				auto info = coawait(link_transactions(listener->asset, &listener->options));
				if (!info)
				{
					if (info.error().is_retry())
					{
						if (protocol::now().user.oracle.logging)
							VI_INFO("%s server data collection: finalized", algorithm::asset::name_of(listener->asset).c_str());

						call_transaction_listener(listener);
						coreturn_void;
					}

					umutex<std::recursive_mutex> unique(control_sys.sync);
					if (control_sys.is_active() && !listener->options.is_cancelled(listener->asset))
					{
						auto id = "transactions_" + algorithm::asset::blockchain_of(listener->asset);
						control_sys.timeout_if_none(id, options.retry_waiting_time_ms, [this, listener, id = std::move(id)]() mutable
						{
							control_sys.clear_timeout(id);
							call_transaction_listener(listener);
						});
						if (protocol::now().user.oracle.logging)
							VI_ERR("%s server data collection: waiting for connection (%s)", algorithm::asset::name_of(listener->asset).c_str(), info.error().what());
					}
					else
						listener->is_dead = true;
					coreturn_void;
				}
				else if (info->finalized.empty() && info->pending.empty())
				{
					if (!info->block_hash.empty())
					{
						if (protocol::now().user.oracle.logging)
							VI_INFO("%s block %s accepted (height: %i, progress: %.2f%%, txns: 0)",
							algorithm::asset::name_of(listener->asset).c_str(),
							info->block_hash.c_str(),
							(int)info->block_height,
							listener->options.get_checkpoint_percentage());
					}

					for (auto& item : callbacks)
						item.second(listener->asset, listener->options, std::move(*info)).report("failed to dispatch transaction logs");;

					call_transaction_listener(listener);
					coreturn_void;
				}
				else if (protocol::now().user.oracle.logging)
					VI_INFO("%s block %s accepted (height: %i, progress: %.2f%%, txns: %i)",
					algorithm::asset::name_of(listener->asset).c_str(),
					info->block_hash.c_str(),
					(int)info->block_height,
					listener->options.get_checkpoint_percentage(),
					(int)info->pending.size() + (int)info->finalized.size());

				if (protocol::now().user.oracle.logging)
				{
					for (auto& tx : info->pending)
						VI_INFO("%s transaction %s accepted (block: %" PRIu64 ", status: pending)", algorithm::asset::name_of(listener->asset).c_str(), tx.transaction_id.c_str(), tx.block_id);

					for (auto& tx : info->finalized)
					{
						string transfer_logs = stringify::text(
							"%s transaction %s accepted (block: %" PRIu64 ", status: finalized)\n",
							algorithm::asset::name_of(listener->asset).c_str(),
							tx.transaction_id.c_str(), tx.block_id);
						for (auto& [hash, input] : tx.inputs)
						{
							transfer_logs += stringify::text("  %s spends %s %s\n", input.link.as_name().c_str(), input.value.to_string().c_str(), algorithm::asset::name_of(listener->asset).c_str());
							for (auto& [token_hash, token] : input.tokens)
								transfer_logs += stringify::text("    with %s %s\n", token.value.to_string().c_str(), algorithm::asset::name_of(token.get_asset(listener->asset)).c_str());
						}
						for (auto& [hash, output] : tx.outputs)
						{
							transfer_logs += stringify::text("  %s receives %s %s\n", output.link.as_name().c_str(), output.value.to_string().c_str(), algorithm::asset::name_of(listener->asset).c_str());
							for (auto& [token_hash, token] : output.tokens)
								transfer_logs += stringify::text("    with %s %s\n", token.value.to_string().c_str(), algorithm::asset::name_of(token.get_asset(listener->asset)).c_str());
						}
						if (transfer_logs.back() == '\n')
							transfer_logs.erase(transfer_logs.end() - 1);

						VI_INFO("%s", transfer_logs.c_str());
					};
				}

				for (auto& item : callbacks)
					item.second(listener->asset, listener->options, std::move(*info)).report("failed to dispatch transaction logs");

				call_transaction_listener(listener);
				coreturn_void;
			}, true).when(std::bind(&server_node::remove_activity_listener, this, listener));
			return true;
		}
		void server_node::startup()
		{
			if (!protocol::now().user.oracle.server)
				return;
			else if (!options.retry_waiting_time_ms || !control_sys.activate())
				return;

			if (protocol::now().user.oracle.logging)
				VI_INFO("oracle node startup");

			unordered_set<string> blockchains;
			blockchains.reserve(nodes.size());
			for (auto& implementation : nodes)
			{
				blockchains.insert(implementation.first);
				for (auto& node : implementation.second)
					node->allow_activities();
			}

			listeners.reserve(blockchains.size());
			for (auto& blockchain : blockchains)
			{
				transaction_listener* listener = memory::init<transaction_listener>();
				listener->asset = algorithm::asset::id_of(blockchain);
				listeners.emplace_back(listener);

				auto& suboptions = *(supervisor_options*)&listener->options;
				suboptions = *(supervisor_options*)&options;

				auto it = options.specifics.find(blockchain);
				if (it != options.specifics.end())
					listener->options = it->second;

				if (!call_transaction_listener(listener))
					return shutdown();

				connections.insert(algorithm::asset::blockchain_of(listener->asset));
			}
		}
		void server_node::shutdown()
		{
			if (!control_sys.deactivate())
				return;

			if (protocol::now().user.oracle.logging)
				VI_INFO("oracle node shutdown");
			{
				umutex<std::recursive_mutex> unique(control_sys.sync);
				for (auto& nodes : nodes)
				{
					for (auto& node : nodes.second)
						node->cancel_activities();
				}
			}
			{
				umutex<std::mutex> unique(activity.mutex);
				auto yield = [&]()
				{
					unique.unlock();
					std::this_thread::sleep_for(std::chrono::microseconds(100));
					unique.lock();
				};
				while (!activity.requests.empty())
				{
					for (auto& request : activity.requests)
					{
						auto* stream = request->get_stream();
						if (stream != nullptr)
							stream->shutdown(true);
					}
					yield();
				}
				while (!activity.listeners.empty())
					yield();
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
		bool server_node::has_oracle(const algorithm::asset_id& asset)
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