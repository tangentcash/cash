#include "chain.h"
#include "script.h"
#include "superchain.h"
#include <rocksdb/db.h>
#include <rocksdb/table.h>
#define KEY_FRONT 32
#define KEY_BACK 32
#define KEY_SIZE 2048

namespace tangent
{
	static rocksdb::Options blob_storage_configuration(storage_optimization type, uint64_t blob_cache_size)
	{
		rocksdb::BlockBasedTableOptions table_options;
		table_options.block_cache = rocksdb::NewLRUCache(blob_cache_size);

		rocksdb::Options options;
		options.create_if_missing = true;
		options.table_factory.reset(rocksdb::NewBlockBasedTableFactory(table_options));
		switch (type)
		{
			case tangent::storage_optimization::speed:
				options.writable_file_max_buffer_size = 1024 * 1024 * 48;
				options.avoid_unnecessary_blocking_io = true;
				break;
			case tangent::storage_optimization::safety:
			default:
				break;
		}
		return options;
	}
	static string index_storage_configuration(storage_optimization type, uint64_t index_page_size, int64_t index_cache_size)
	{
		switch (type)
		{
			case tangent::storage_optimization::speed:
				return stringify::text(
					"PRAGMA journal_mode = WAL;"
					"PRAGMA synchronous = off;"
					"PRAGMA temp_store = memory;"
					"PRAGMA mmap_size = 68719476736;"
					"PRAGMA page_size = %" PRIu64 ";"
					"PRAGMA cache_size = %" PRIi64 ";", index_page_size, index_cache_size);
			case tangent::storage_optimization::safety:
			default:
				return stringify::text(
					"PRAGMA journal_mode = WAL;"
					"PRAGMA synchronous = normal;"
					"PRAGMA temp_store = file;"
					"PRAGMA mmap_size = 68719476736;"
					"PRAGMA page_size = %" PRIu64 ";"
					"PRAGMA cache_size = %" PRIi64 ";", index_page_size, index_cache_size);
		}
	}

	layer_exception::layer_exception() : std::exception()
	{
	}
	layer_exception::layer_exception(string&& text) : std::exception(), error_message(std::move(text))
	{
	}
	layer_exception::layer_exception(const layer_exception& other) : std::exception(), error_message(other.error_message)
	{
	}
	layer_exception::layer_exception(layer_exception&& other) noexcept : std::exception(), error_message(std::move(other.error_message))
	{
	}
	layer_exception& layer_exception::operator=(const layer_exception& other)
	{
		if (this == &other)
			return *this;

		error_message = other.error_message;
		return *this;
	}
	layer_exception& layer_exception::operator=(layer_exception&& other) noexcept
	{
		if (this == &other)
			return *this;

		error_message = std::move(other.error_message);
		return *this;
	}
	const char* layer_exception::what() const noexcept
	{
		return error_message.c_str();
	}
	string&& layer_exception::message() noexcept
	{
		return std::move(error_message);
	}

	remote_exception::remote_exception() : remote_exception(string(), 1, 0)
	{
	}
	remote_exception::remote_exception(string&& text, int8_t new_status, uint64_t new_retry_time) : std::exception(), error_message(std::move(text)), error_status(new_status), error_retry_time(new_retry_time)
	{
		if (error_message.empty() && error_status > 0)
			error_message = "result unavailable now";
		else if (error_message.empty() && error_status < 0)
			error_message = "shutdown requested";
	}
	remote_exception::remote_exception(string&& text) : std::exception(), error_message(std::move(text)), error_status(0)
	{
	}
	remote_exception::remote_exception(const remote_exception& other) : std::exception(), error_message(other.error_message), error_status(other.error_status), error_retry_time(other.error_retry_time)
	{
	}
	remote_exception::remote_exception(remote_exception&& other) noexcept : std::exception(), error_message(std::move(other.error_message)), error_status(other.error_status), error_retry_time(other.error_retry_time)
	{
	}
	remote_exception& remote_exception::operator=(const remote_exception& other)
	{
		if (this == &other)
			return *this;

		error_message = other.error_message;
		error_status = other.error_status;
		error_retry_time = other.error_retry_time;
		return *this;
	}
	remote_exception& remote_exception::operator=(remote_exception&& other) noexcept
	{
		if (this == &other)
			return *this;

		error_message = std::move(other.error_message);
		error_status = other.error_status;
		error_retry_time = other.error_retry_time;
		return *this;
	}
	const char* remote_exception::what() const noexcept
	{
		return error_message.c_str();
	}
	string&& remote_exception::message() noexcept
	{
		return std::move(error_message);
	}
	uint64_t remote_exception::retry_after_timestamp() const noexcept
	{
		return error_retry_time;
	}
	bool remote_exception::is_retry_after() const noexcept
	{
		return is_retry() && error_retry_time > 0;
	}
	bool remote_exception::is_retry() const noexcept
	{
		return error_status > 0;
	}
	bool remote_exception::is_shutdown() const noexcept
	{
		return error_status < 0;
	}
	remote_exception remote_exception::retry_later(string&& text)
	{
		return remote_exception(std::move(text), 1, 0);
	}
	remote_exception remote_exception::retry_after(uint64_t timestamp, string&& text)
	{
		return remote_exception(std::move(text), 1, timestamp);
	}
	remote_exception remote_exception::shutdown(string&& text)
	{
		return remote_exception(std::move(text), -1, 0);
	}

	repository::~repository()
	{
		for (auto& handle : blobs)
		{
			if (handle.second)
				handle.second->Close();
		}
		blobs.clear();
	}
	rocksdb::DB* repository::pull_blob_ref(const std::string_view& location)
	{
		umutex<std::mutex> unique(mutex);
		if (target_path.empty())
			resolve(protocol::now().user.network, protocol::now().user.storage.path);

		string address = stringify::text("%s%.*sdb", target_path.c_str(), (int)location.size(), location.data());
		auto it = blobs.find(address);
		if (it != blobs.end() && it->second)
			return it->second;

		auto config = blob_storage_configuration(protocol::now().user.storage.optimization, protocol::now().user.storage.blob_cache_size);
		auto path = std::string(address.begin(), address.end());
		std::unique_ptr<rocksdb::DB> result;
		auto status = rocksdb::DB::Open(config, path, &result);
		if (!status.ok())
		{
			if (protocol::now().user.storage.logging)
				VI_ERR("wal append error: %s (location: %s)", status.ToString().c_str(), address.c_str());

			return nullptr;
		}

		if (protocol::now().user.storage.logging)
			VI_DEBUG("wal append on %s (handle: 0x%" PRIXPTR ")", address.c_str(), (uintptr_t)result.get());

		auto threads = os::hw::get_quantity_info().physical;
		auto options = result->GetOptions();
		if (protocol::now().user.storage.compaction_threads_ratio > 0.0)
			options.env->SetBackgroundThreads((int)std::max(std::ceil(threads * protocol::now().user.storage.compaction_threads_ratio), 1.0), rocksdb::Env::Priority::LOW);
		if (protocol::now().user.storage.flush_threads_ratio > 0.0)
			options.env->SetBackgroundThreads((int)std::max(std::ceil(threads * protocol::now().user.storage.flush_threads_ratio), 1.0), rocksdb::Env::Priority::HIGH);

		blobs[address] = result.get();
		return result.release();
	}
	uref<sqlite::connection> repository::pull_index(const std::string_view& location, std::function<void(sqlite::connection*)>&& initializer)
	{
		umutex<std::mutex> unique(mutex);
		if (target_path.empty())
			resolve(protocol::now().user.network, protocol::now().user.storage.path);

		std::string_view prefix = "file:///";
		std::string_view postfix = ".db";
		char buffer[3072] = { 0 };
		memcpy(buffer, prefix.data(), prefix.size());
		memcpy(buffer + prefix.size(), target_path.data(), target_path.size());
		memcpy(buffer + prefix.size() + target_path.size(), location.data(), location.size());
		memcpy(buffer + prefix.size() + target_path.size() + location.size(), postfix.data(), postfix.size());

		std::string_view address = std::string_view(buffer, strnlen(buffer, sizeof(buffer)));
		uref<sqlite::connection> result;
		auto it = indices.find(address);
		if (it != indices.end() && !it->second.empty())
		{
			result = std::move(it->second.front());
			it->second.pop();
			return result;
		}

		result = new sqlite::connection();
		auto status = result->connect(address);
		if (!status)
		{
			if (protocol::now().user.storage.logging)
				VI_ERR("wal append error: %s (location: %.*s)", status.error().what(), (int)address.size(), address.data());

			return result;
		}

		if (!result->query(index_storage_configuration(protocol::now().user.storage.optimization, protocol::now().user.storage.index_page_size, protocol::now().user.storage.index_cache_size)))
			return result;

		if (initializer)
			initializer(*result);

		if (protocol::now().user.storage.logging)
			VI_DEBUG("wal append on %s (handle: 0x%" PRIXPTR ")", address.c_str(), (uintptr_t)*result);

		return result;
	}
	void repository::push_index(uref<sqlite::connection>&& value)
	{
		VI_ASSERT(value, "connection should be set");
		if (value->get_ref_count() > 1)
			return value.destroy();

		umutex<std::mutex> unique(mutex);
		auto& queue = indices[value->get_address()];
		queue.push(std::move(value));
	}
	void repository::reset()
	{
		umutex<std::mutex> unique(mutex);
		for (auto& handle : blobs)
		{
			if (handle.second)
				handle.second->Close();
			delete handle.second;
		}
		blobs.clear();
		indices.clear();
		target_path.clear();
	}
	void repository::checkpoint()
	{
		umutex<std::mutex> unique(mutex);
		for (auto& handle : blobs)
		{
			if (!handle.second)
				continue;

			rocksdb::FlushOptions options;
			options.allow_write_stall = true;
			options.wait = true;

			auto status = handle.second->Flush(options);
			if (protocol::now().user.storage.logging)
			{
				if (status.ok())
					VI_INFO("blob storage checkpoint on %s", handle.first.c_str());
				else
					VI_ERR("blob storage checkpoint error on: %s (location: %s)", status.ToString().c_str(), handle.first.c_str());
			}
		}

		for (auto& queue : indices)
		{
			if (queue.second.empty())
				continue;

			auto& handle = queue.second.front();
			auto states = handle->wal_checkpoint(sqlite::checkpoint_mode::truncate);
			if (protocol::now().user.storage.logging)
			{
				for (auto& state : states)
					VI_INFO("index storage checkpoint on %s (db: %s, fc: %i, fs: %i, stat: %i)", queue.first.c_str(), state.database.empty() ? "all" : state.database.c_str(), state.frames_count, state.frames_size, state.status);
			}
		}
	}
	const string& repository::resolve(network_type type, const std::string_view& path)
	{
		if (!target_path.empty())
			return target_path;

		auto module_path = os::directory::get_module();
		if (!module_path->empty() && module_path->back() != '/' && module_path->back() != '\\')
			*module_path += VI_SPLITTER;

		auto absolute_path = os::path::resolve(path, *module_path, true);
		string base_path = absolute_path ? *absolute_path : *module_path + string(path);
		if (!base_path.empty() && base_path.back() != '/' && base_path.back() != '\\')
			base_path += VI_SPLITTER;

		switch (type)
		{
			case network_type::regtest:
				base_path += "regtest";
				break;
			case network_type::testnet:
				base_path += "testnet";
				break;
			case network_type::mainnet:
				base_path += "mainnet";
				break;
			default:
				VI_PANIC(false, "invalid network type");
				break;
		}

		base_path += VI_SPLITTER;
		auto resolved_path = os::path::resolve(base_path);
		VI_PANIC(resolved_path && os::directory::patch(*resolved_path), "invalid storage path: %s", base_path.c_str());
		target_path = std::move(*resolved_path);
		if (!target_path.empty() && target_path.back() != '/' && target_path.back() != '\\')
			target_path += VI_SPLITTER;
		return target_path;
	}
	const string repository::location() const
	{
		return target_path;
	}

	string keystate::init(const std::string_view& maybe_data, bool interactive)
	{
		VI_PANIC(maybe_data.empty() || maybe_data.size() == KEY_SIZE + 32, "base keystate must be either empty or unencrypted")
		auto entropy = maybe_data.empty() ? *crypto::random_bytes(KEY_SIZE) : string(maybe_data.substr(0, KEY_SIZE));
		auto commitment = *crypto::hash(digests::sha256(), entropy);
		VI_PANIC(maybe_data.empty() || commitment == maybe_data.substr(maybe_data.size() - 32), "base keystate checksum validation failed");
		if (interactive)
		{
			string password;
			auto* terminal = console::get();
			terminal->fwrite("%s keystate password: ", maybe_data.empty() ? "new" : "attach");
			terminal->echo_off([&]() { password = terminal->read(1024); });
			terminal->write("verify keystate password: ");
			terminal->echo_off([&]() { VI_PANIC(!password.empty() && terminal->read(1024) == password, "password verification failed"); });

			uint8_t encryption_key[32] = { 0 }, encryption_salt[16] = { 0 };
			VI_PANIC(algorithm::signing::derive_seed_from_password((uint8_t*)password.data(), password.size(), encryption_key, sizeof(encryption_key)), "encryption key derivation failed");
			crypto::fill_random_bytes(encryption_salt, sizeof(encryption_salt)).expect("encryption salt generation failed");

			auto encryption_key_view = secret_box::view(std::string_view((char*)encryption_key, sizeof(encryption_key)));
			auto encryption_salt_view = secret_box::view(std::string_view((char*)encryption_salt, sizeof(encryption_salt)));
			entropy = crypto::encrypt(ciphers::aes_256_cbc(), entropy, encryption_key_view, encryption_salt_view).expect("keystate encryption failed");
			entropy.append(std::string_view((char*)encryption_salt, sizeof(encryption_salt)));
		}
		entropy.append(commitment);
		return entropy;
	}
	void keystate::use(network_type type, const std::string_view& data, bool interactive)
	{
		VI_PANIC(interactive ? data.size() >= KEY_SIZE + 48 : (data.size() == KEY_SIZE + 32), "invalid keystate size");
		auto calculate = [&](const std::string_view& entropy)
		{
			string blob = to_string((uint8_t)type).append(entropy);
			for (size_t i = 0; i < entropy.size(); i++)
				blob = *crypto::hash(digests::sha256(), blob);
			key = secret_box::secure(blob);
		};
		if (interactive)
		{
			auto password = os::process::get_env("XBASE");
			if (!password)
			{
				auto* terminal = console::get();
				terminal->write("keystate password: ");
				terminal->echo_off([&]() { password = terminal->read(1024); });
			}

			uint8_t encryption_key[32] = { 0 };
			VI_PANIC(algorithm::signing::derive_seed_from_password((uint8_t*)password->data(), password->size(), encryption_key, sizeof(encryption_key)), "decryption key derivation failed");

			auto encryption_key_view = secret_box::view(std::string_view((char*)encryption_key, sizeof(encryption_key)));
			auto encryption_salt_view = secret_box::view(data.substr(data.size() - 48, 16));
			auto entropy = crypto::decrypt(ciphers::aes_256_cbc(), data.substr(0, data.size() - 48), encryption_key_view, encryption_salt_view).expect("keystate decryption failed");

			VI_PANIC(*crypto::hash(digests::sha256(), entropy) == data.substr(data.size() - 32), "keystate checksum validation failed");
			entropy.append(data.substr(data.size() - 32));
			calculate(entropy);
		}
		else
		{
			VI_PANIC(*crypto::hash(digests::sha256(), data.substr(0, data.size() - 32)) == data.substr(data.size() - 32), "keystate checksum validation failed");
			calculate(data);
		}
	}
	expects_lr<string> keystate::encrypt(const std::string_view& data) const
	{
		auto front = *crypto::random_bytes(KEY_FRONT), back = *crypto::random_bytes(KEY_BACK);
		auto salt = crypto::hash(digests::sha256(), front + back);
		auto result = crypto::encrypt(ciphers::aes_256_cbc(), data, key, secret_box::view(*salt));
		result.report("secret value encryption failed (keystate possibly invalid)");
		if (!result)
			return layer_exception(std::move(result.error().message()));

		result->insert(result->begin(), front.begin(), front.end());
		result->append(back);
		return *result;
	}
	expects_lr<string> keystate::decrypt(const std::string_view& data) const
	{
		if (data.size() <= KEY_FRONT + KEY_BACK)
			return layer_exception("invalid blob");

		auto front = data.substr(0, KEY_FRONT), back = data.substr(data.size() - KEY_BACK);
		auto salt = crypto::hash(digests::sha256(), string(front) + string(back));
		auto result = crypto::decrypt(ciphers::aes_256_cbc(), data.substr(KEY_FRONT, data.size() - KEY_FRONT - KEY_BACK), key, secret_box::view(*salt));
		result.report("secret value decryption failed (keystate possibly invalid)");
		if (!result)
			return layer_exception(std::move(result.error().message()));

		return *result;
	}

	string timepoint::adjust(const socket_address& address, int64_t milliseconds_delta)
	{
		string source = address.get_ip_address().or_else("[bad_address]") + ":" + to_string(address.get_ip_port().or_else(0));
		umutex<std::mutex> unique(mutex);
		size_t sources = offsets.size();
		if (milliseconds_delta != 0)
		{
			auto it = offsets.find(source);
			if (it == offsets.end())
			{
				offsets[source] = milliseconds_delta;
				++sources;
			}
			else
				it->second = milliseconds_delta;
		}
		else
			offsets.erase(source);

		if (offsets.size() < 5 || offsets.size() % 2 != 1)
			return string();

		using time_source = std::pair<std::string_view, int64_t>;
		vector<time_source> time_offsets;
		time_offsets.reserve(offsets.size());
		for (auto& item : offsets)
			time_offsets.push_back(std::make_pair(std::string_view(item.first), item.second));

		auto& message = protocol::now().message;
		std::sort(time_offsets.begin(), time_offsets.end(), [](const time_source& a, const time_source& b)
		{
			return a.second < b.second;
		});

		bool is_severe_desync = false;
		auto& median_time = time_offsets[time_offsets.size() / 2];
		if (median_time.second > (int64_t)message.timestamp_delta)
		{
			median_time.second = (int64_t)message.timestamp_delta;
			is_severe_desync = true;
		}
		else if (median_time.second < -(int64_t)message.timestamp_delta)
		{
			median_time.second = -(int64_t)message.timestamp_delta;
			is_severe_desync = true;
		}

		milliseconds_offset = median_time.second;
		if (is_severe_desync)
			return string(median_time.first);

		return string();
	}
	uint64_t timepoint::now() const
	{
		return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count() + milliseconds_offset;
	}
	uint64_t timepoint::now_cpu() const
	{
		return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
	}

	void protocol::logger::output(const std::string_view& message)
	{
		if (!resource || message.empty())
			return;

		time_t archive_time = ::time(nullptr);
		umutex<std::recursive_mutex> unique(mutex);
		resource->write((uint8_t*)message.data(), message.size());
		if (message.back() != '\r' && message.back() != '\n')
			resource->write((uint8_t*)"\n", 1);

		if (!protocol::bound() || archive_time - repack_time < (int64_t)protocol::now().user.logs.archive_repack_interval / 1000)
			return;

		auto state = os::file::get_properties(resource->virtual_name());
		size_t current_size = state ? state->size : 0;
		repack_time = archive_time;
		if (current_size <= protocol::now().user.logs.archive_size)
			return;

		string archive_path = string(resource->virtual_name());
		resource = os::file::open_archive(archive_path, protocol::now().user.logs.archive_size).or_else(nullptr);
	}

	protocol::protocol(const inline_args& environment)
	{
		if (!environment.params.empty())
			path = environment.params.back();

		auto library = os::directory::get_module();
		if (!path.empty())
			path = os::path::resolve(path, *library, true).or_else(string(path));

		error_handling::set_flag(log_option::pretty, true);
		error_handling::set_flag(log_option::dated, true);
		error_handling::set_flag(log_option::active, true);
		os::directory::set_working(library->c_str());
		console::get()->attach();

		option<format::tree> config = path.empty() ? option<format::tree>(optional::none) : option<format::tree>(*format::tree::from_json(*os::file::read_as_string(path)));
		if (!environment.args.empty())
		{
			if (!config)
				config = format::tree::map();
			for (auto& [key, value] : environment.args)
			{
				auto* parent = config.address();
				for (auto& name : stringify::split(key, '.'))
				{
					auto child = (format::tree*)parent->child(name);
					parent = (child ? child : parent->set(name, format::tree()));
				}
				parent->value = format::variable::from(value);
			}
		}
		if (config)
		{
			auto* value = config->child("network");
			if (value != nullptr && value->value.is_string())
			{
				auto type = value->value.as_string();
				if (type == "mainnet")
					user.network = network_type::mainnet;
				else if (type == "testnet")
					user.network = network_type::testnet;
				else if (type == "regtest")
					user.network = network_type::regtest;
			}

			value = config->child("keystate");
			if (value != nullptr && value->value.is_string())
				user.keystate = value->value.as_blob();

			value = config->child("interactive");
			if (value != nullptr && value->value.is_boolean())
				user.interactive = value->value.as_boolean();

			value = config->child("known_nodes");
			if (value != nullptr && value->is_list())
			{
				for (auto& seed : value->childs())
				{
					if (seed.value.is_string())
						user.known_nodes.insert(seed.value.as_blob());
				}
			}

			value = config->child("bootstrap_nodes");
			if (value != nullptr && value->is_list())
			{
				for (auto& seed : value->childs())
				{
					if (seed.value.is_string())
						user.bootstrap_nodes.insert(seed.value.as_blob());
				}
			}

			value = config->child("consensus.accounts");
			if (value != nullptr && value->is_list())
			{
				for (auto& account_secret : value->childs())
				{
					if (account_secret.value.is_string())
						user.consensus.accounts.push_back(account_secret.value.as_blob());
				}
			}

			value = config->child("consensus.address");
			if (value != nullptr && value->value.is_string())
				user.consensus.address = value->value.as_blob();

			value = config->child("consensus.port");
			if (value != nullptr && value->value.is_integer())
				user.consensus.port = value->value.as_uint16();

			value = config->child("consensus.max_inbound_connections");
			if (value != nullptr && value->value.is_integer())
				user.consensus.max_inbound_connections = value->value.as_uint32();

			value = config->child("consensus.max_outbound_connections");
			if (value != nullptr && value->value.is_integer())
				user.consensus.max_outbound_connections = value->value.as_uint32();

			value = config->child("consensus.inventory_timeout");
			if (value != nullptr && value->value.is_integer())
				user.consensus.inventory_timeout = value->value.as_uint64();

			value = config->child("consensus.inventory_size");
			if (value != nullptr && value->value.is_integer())
				user.consensus.inventory_size = value->value.as_uint32();

			value = config->child("consensus.aggregation_attempts");
			if (value != nullptr && value->value.is_integer())
				user.consensus.aggregation_attempts = value->value.as_uint64();

			value = config->child("consensus.aggregation_cooldown");
			if (value != nullptr && value->value.is_integer())
				user.consensus.aggregation_cooldown = value->value.as_uint64();

			value = config->child("consensus.coordination_attempts");
			if (value != nullptr && value->value.is_integer())
				user.consensus.coordination_attempts = value->value.as_uint8();

			value = config->child("consensus.reorganizable");
			if (value != nullptr && value->value.is_boolean())
				user.consensus.reorganizable = value->value.as_boolean();

			value = config->child("consensus.miner");
			if (value != nullptr && value->value.is_boolean())
				user.consensus.miner = value->value.as_boolean();

			value = config->child("consensus.server");
			if (value != nullptr && value->value.is_boolean())
				user.consensus.server = value->value.as_boolean();

			value = config->child("consensus.logging");
			if (value != nullptr && value->value.is_boolean())
				user.consensus.logging = value->value.as_boolean();

			value = config->child("discovery.address");
			if (value != nullptr && value->value.is_string())
				user.discovery.address = value->value.as_string();

			value = config->child("discovery.port");
			if (value != nullptr && value->value.is_integer())
				user.discovery.port = value->value.as_uint16();

			value = config->child("discovery.server");
			if (value != nullptr && value->value.is_boolean())
				user.discovery.server = value->value.as_boolean();

			value = config->child("discovery.logging");
			if (value != nullptr && value->value.is_boolean())
				user.discovery.logging = value->value.as_boolean();

			value = config->child("superchain.polling_frequency");
			if (value != nullptr && value->value.is_integer())
				user.superchain.polling_frequency = value->value.as_uint64();

			value = config->child("superchain.cache1_size");
			if (value != nullptr && value->value.is_integer())
				user.superchain.cache1_size = value->value.as_uint32();

			value = config->child("superchain.cache2_size");
			if (value != nullptr && value->value.is_integer())
				user.superchain.cache2_size = value->value.as_uint32();

			value = config->child("superchain.listener");
			if (value != nullptr && value->value.is_boolean())
				user.superchain.listener = value->value.as_boolean();

			value = config->child("superchain.logging");
			if (value != nullptr && value->value.is_boolean())
				user.superchain.logging = value->value.as_boolean();

			value = config->child("rpc.address");
			if (value != nullptr && value->value.is_string())
				user.rpc.address = value->value.as_blob();

			value = config->child("rpc.port");
			if (value != nullptr && value->value.is_integer())
				user.rpc.port = value->value.as_uint16();

			value = config->child("rpc.useranme");
			if (value != nullptr && value->value.is_string())
				user.rpc.username = value->value.as_blob();

			value = config->child("rpc.password");
			if (value != nullptr && value->value.is_string())
				user.rpc.password = value->value.as_blob();

			value = config->child("rpc.sandbox");
			if (value != nullptr && value->value.is_boolean())
				user.rpc.sandbox = value->value.as_boolean();

			value = config->child("rpc.server");
			if (value != nullptr && value->value.is_boolean())
				user.rpc.server = value->value.as_boolean();

			value = config->child("rpc.logging");
			if (value != nullptr && value->value.is_boolean())
				user.rpc.logging = value->value.as_boolean();

			value = config->child("tcp.tls_trusted_peers");
			if (value != nullptr && value->value.is_integer())
				user.tcp.tls_trusted_peers = value->value.as_uint64();

			value = config->child("tcp.mbps_per_socket");
			if (value != nullptr && value->value.is_integer())
				user.tcp.mbps_per_socket = value->value.as_uint64();

			value = config->child("tcp.timeout");
			if (value != nullptr && value->value.is_integer())
				user.tcp.timeout = value->value.as_uint64();

			value = config->child("tcp.keep_alive");
			if (value != nullptr && value->value.is_integer())
				user.tcp.keep_alive = value->value.as_uint64();

			value = config->child("storage.path");
			if (value != nullptr && value->value.is_string())
				user.storage.path = value->value.as_blob();

			value = config->child("storage.module_cache_path");
			if (value != nullptr && value->value.is_string())
				user.storage.module_cache_path = value->value.as_blob();

			value = config->child("storage.optimization");
			if (value != nullptr && value->value.is_string())
			{
				auto type = value->value.as_blob();
				if (type == "speed")
					user.storage.optimization = storage_optimization::speed;
				else if (type == "safety")
					user.storage.optimization = storage_optimization::safety;
			}

			value = config->child("storage.checkpoint_size");
			if (value != nullptr && value->value.is_integer())
				user.storage.checkpoint_size = value->value.as_uint64();

			value = config->child("storage.max_tree_queue_size");
			if (value != nullptr && value->value.is_integer())
				format::tree_pool::get()->max_queue_size = (size_t)value->value.as_uint64();

			value = config->child("storage.max_tree_vector_size");
			if (value != nullptr && value->value.is_integer())
				format::tree_pool::get()->max_vector_capacity = (size_t)value->value.as_uint64();

			value = config->child("storage.module_cache_size");
			if (value != nullptr && value->value.is_integer())
				user.storage.module_cache_size = value->value.as_uint64();

			value = config->child("storage.blob_cache_size");
			if (value != nullptr && value->value.is_integer())
				user.storage.blob_cache_size = value->value.as_uint64();

			value = config->child("storage.index_page_size");
			if (value != nullptr && value->value.is_integer())
				user.storage.index_page_size = value->value.as_uint64();

			value = config->child("storage.index_cache_size");
			if (value != nullptr && value->value.is_integer())
				user.storage.index_cache_size = value->value.as_uint64();

			value = config->child("storage.flush_threads_ratio");
			if (value != nullptr && value->value.is_decimal())
				user.storage.flush_threads_ratio = value->value.as_double();

			value = config->child("storage.compaction_threads_ratio");
			if (value != nullptr && value->value.is_decimal())
				user.storage.compaction_threads_ratio = value->value.as_double();

			value = config->child("storage.computation_threads_ratio");
			if (value != nullptr && value->value.is_decimal())
				user.storage.computation_threads_ratio = value->value.as_double();

			value = config->child("storage.transaction_to_account_index");
			if (value != nullptr && value->value.is_boolean())
				user.storage.transaction_to_account_index = value->value.as_boolean();

			value = config->child("storage.transaction_to_alias_index");
			if (value != nullptr && value->value.is_boolean())
				user.storage.transaction_to_alias_index = value->value.as_boolean();

			value = config->child("storage.logging");
			if (value != nullptr && value->value.is_boolean())
				user.storage.logging = value->value.as_boolean();

			value = config->child("logs.info");
			if (value != nullptr && value->value.is_string())
				user.logs.info_path = value->value.as_blob();

			value = config->child("logs.error");
			if (value != nullptr && value->value.is_string())
				user.logs.error_path = value->value.as_blob();

			value = config->child("logs.query");
			if (value != nullptr && value->value.is_string())
				user.logs.query_path = value->value.as_blob();

			value = config->child("logs.archive_size");
			if (value != nullptr && value->value.is_integer())
				user.logs.archive_size = value->value.as_uint64();

			value = config->child("logs.archive_repack_interval");
			if (value != nullptr && value->value.is_integer())
				user.logs.archive_repack_interval = value->value.as_uint64();

			value = config->child("logs.control_logging");
			if (value != nullptr && value->value.is_boolean())
				user.logs.control_logging = value->value.as_boolean();

			auto superchain_options = config->child("superchain");
			if (superchain_options)
				user.superchain.options = memory::init<format::tree>(std::move(*superchain_options));
		}
		else
			path.clear();

		if (user.storage.path.empty())
		{
#ifdef VI_MICROSOFT
			user.storage.path = "./";
#else
			user.storage.path = "/var/lib/tangentcash/";
#endif
		}

		auto database_path = database.resolve(user.network, user.storage.path);
		if (!user.storage.module_cache_path.empty())
		{
			auto module_path = os::path::resolve(user.storage.module_cache_path, user.storage.path, true).or_else(user.storage.module_cache_path);
			stringify::eval_envs(module_path, os::path::get_directory(module_path), vitex::network::utils::get_host_ip_addresses());
			os::directory::patch(module_path);
			if (!module_path.empty() && (module_path.back() == '/' || module_path.back() == '\\'))
				module_path.pop_back();
			user.storage.module_cache_path = std::move(module_path);
		}

		if (!user.logs.info_path.empty())
		{
			auto log_base = database_path + user.logs.info_path;
			auto log_path = os::path::resolve(os::path::resolve(log_base, *library, true).or_else(user.logs.info_path)).or_else(user.logs.info_path);
			stringify::eval_envs(log_path, os::path::get_directory(log_path), vitex::network::utils::get_host_ip_addresses());
			os::directory::patch(os::path::get_directory(log_path));
			if (!log_path.empty())
				logs.info.resource = os::file::open_archive(log_path, user.logs.archive_size).or_else(nullptr);
		}

		if (!user.logs.error_path.empty())
		{
			auto log_base = database_path + user.logs.error_path;
			auto log_path = os::path::resolve(os::path::resolve(log_base, *library, true).or_else(user.logs.error_path)).or_else(user.logs.error_path);
			stringify::eval_envs(log_path, os::path::get_directory(log_path), vitex::network::utils::get_host_ip_addresses());
			os::directory::patch(os::path::get_directory(log_path));
			if (!log_path.empty())
				logs.error.resource = os::file::open_archive(log_path, user.logs.archive_size).or_else(nullptr);
		}

		if (!user.logs.query_path.empty())
		{
			auto log_base = database_path + user.logs.query_path;
			auto log_path = os::path::resolve(os::path::resolve(log_base, *library, true).or_else(user.logs.query_path)).or_else(user.logs.query_path);
			stringify::eval_envs(log_path, os::path::get_directory(log_path), vitex::network::utils::get_host_ip_addresses());
			os::directory::patch(os::path::get_directory(log_path));
			if (!log_path.empty())
			{
				logs.query.resource = os::file::open_archive(log_path, user.logs.archive_size).or_else(nullptr);
				if (logs.query.resource)
					sqlite::driver::get()->set_query_log([this](const std::string_view& data) { logs.query.output(data); });
			}
		}

		if (logs.info.resource || logs.error.resource)
		{
			error_handling::set_callback([this](error_handling::details& data)
			{
				if (data.type.level == log_level::error || data.type.level == log_level::warning || data.type.fatal)
				{
					if (logs.error.resource)
						logs.error.output(error_handling::get_message_text(data));
				}
				else if (logs.info.resource)
					logs.info.output(error_handling::get_message_text(data));
			});
		}

		auto default_keystate_path = std::string_view("./keystate.sk");
		auto keystate_base = user.keystate.empty() ? string(default_keystate_path) : user.keystate;
		auto keystate_url = location(keystate_base);
		auto keystate_host = keystate_url.protocol == "file";
		auto keystate_path = keystate_host ? os::path::resolve(keystate_base, user.storage.path, true).or_else(keystate_base) : keystate_base;
		auto keystate_file = os::file::read_as_string(keystate_path);
		if (!keystate_file)
		{
			if (!keystate_host)
				keystate_path = os::path::resolve(default_keystate_path, user.storage.path, true).or_else(string(default_keystate_path));

			auto* value = config ? config->child("keystate_for_encryption") : nullptr;
			if (value != nullptr && value->value.is_string())
				keystate_file = box.init(*os::file::read_as_string(*os::path::resolve(value->value.as_string(), user.storage.path, true)), user.interactive);
			else
				keystate_file = box.init(std::string_view(), user.interactive);

			VI_PANIC(location(keystate_path).protocol == "file", "cannot save keystate into %s", keystate_path.c_str());
			os::directory::patch(os::path::get_directory(keystate_path)).expect("cannot save keystate into " + keystate_path);
			os::file::write(keystate_path, (uint8_t*)keystate_file->data(), keystate_file->size()).expect("cannot save keystate into " + keystate_path);
		}

		instance = this;
		box.use(user.network, *keystate_file, user.interactive);
		switch (user.network)
		{
			case tangent::network_type::regtest:
				message.packet_magic = 0xe249c307;
				account.secret_key_prefix = "secrt";
				account.public_key_prefix = "pubrt";
				account.address_prefix = "tcrt";
				account.secret_key_version = 0xD;
				account.public_key_version = 0xC;
				account.address_version = 0x6;
				policy.pow.base = "5606b660d1a231b6c24671da42a0c9a0fad602b1d771f43e0c192729938c971201f81b311eadab3417cb5d45ad55f89d74f6946f3d3dad45459af37e8ef7029b";
				policy.pow.time = 1;
				policy.pow.difficulty = 1;
				policy.pow.security = 64;
				policy.attestation.confirmation_time = 2;
				policy.attestation.min_stake_value = decimal::zero();
				policy.participation.locking_time = 2;
				policy.participation.min_stake_value = decimal::zero();
				policy.production.min_network_congestion = 2000000;
				policy.production.min_stake_value = decimal::zero();
				break;
			case tangent::network_type::testnet:
				message.packet_magic = 0xf815c95c;
				account.secret_key_prefix = "sect";
				account.public_key_prefix = "pubt";
				account.address_prefix = "tct";
				account.secret_key_version = 0xE;
				account.public_key_version = 0xD;
				account.address_version = 0x5;
				policy.pow.base = "13c6e158fd95c9e0fb5f61b21cd36f3be9b206669ca0d6bf19449267de4e243c3ba67d6f37d92634cd0b12ea094d2c63d978a9a857691db6576a81ff90ddebff";
				policy.attestation.confirmation_time = 43200000;
				break;
			case tangent::network_type::mainnet:
				break;
			default:
				VI_PANIC(false, "bad network type");
				break;
		}

		uplinks::link_instance();
		algorithm::signing::initialize();
	}
	protocol::~protocol()
	{
		database.checkpoint();
		superchain::bridge::cleanup_instance();
		script::factory::cleanup_instance();
		format::tree_pool::cleanup_instance();
		algorithm::signing::deinitialize();
		error_handling::set_callback(nullptr);
		if (instance == this)
			instance = nullptr;
	}
	bool protocol::is(network_type type) const
	{
		return user.network == type;
	}
	bool protocol::on(fork_id fork, uint64_t block_number) const
	{
		if (user.network != network_type::mainnet)
			return true;

		return block_number >= (uint64_t)fork;
	}
	bool protocol::custom() const
	{
		return !path.empty();
	}
	bool protocol::bound()
	{
		return instance != nullptr;
	}
	protocol& protocol::change()
	{
		VI_ASSERT(instance != nullptr, "chain parameters are not set!");
		return *instance;
	}
	const protocol& protocol::now()
	{
		VI_ASSERT(instance != nullptr, "chain parameters are not set!");
		return *instance;
	}
	protocol* protocol::instance = nullptr;
}
