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
			resolve(kernel::params().user.network, kernel::params().user.storage.path);

		string address = stringify::text("%s%.*sdb", target_path.c_str(), (int)location.size(), location.data());
		auto it = blobs.find(address);
		if (it != blobs.end() && it->second)
			return it->second;

		auto config = blob_storage_configuration(kernel::params().user.storage.optimization, kernel::params().user.storage.blob_cache_size);
		auto path = std::string(address.begin(), address.end());
		std::unique_ptr<rocksdb::DB> result;
		auto status = rocksdb::DB::Open(config, path, &result);
		if (!status.ok())
		{
			if (kernel::params().user.storage.logging)
				VI_ERR("wal append error: %s (location: %s)", status.ToString().c_str(), address.c_str());

			return nullptr;
		}

		if (kernel::params().user.storage.logging)
			VI_DEBUG("wal append on %s (handle: 0x%" PRIXPTR ")", address.c_str(), (uintptr_t)result.get());

		auto threads = os::hw::get_quantity_info().physical;
		auto options = result->GetOptions();
		if (kernel::params().user.storage.compaction_threads_ratio > 0.0)
			options.env->SetBackgroundThreads((int)std::max(std::ceil(threads * kernel::params().user.storage.compaction_threads_ratio), 1.0), rocksdb::Env::Priority::LOW);
		if (kernel::params().user.storage.flush_threads_ratio > 0.0)
			options.env->SetBackgroundThreads((int)std::max(std::ceil(threads * kernel::params().user.storage.flush_threads_ratio), 1.0), rocksdb::Env::Priority::HIGH);

		blobs[address] = result.get();
		return result.release();
	}
	uref<sqlite::connection> repository::pull_index(const std::string_view& location, std::function<void(sqlite::connection*)>&& initializer)
	{
		umutex<std::mutex> unique(mutex);
		if (target_path.empty())
			resolve(kernel::params().user.network, kernel::params().user.storage.path);

		std::string_view prefix = "file:///";
		std::string_view postfix = ".db";
		size_t path_length = prefix.size() + target_path.size() + location.size();
		char buffer[3072] = { 0 };
		VI_PANIC(path_length + postfix.size() <= sizeof(buffer), "database path is too long");
		memcpy(buffer, prefix.data(), prefix.size());
		memcpy(buffer + prefix.size(), target_path.data(), target_path.size());
		memcpy(buffer + prefix.size() + target_path.size(), location.data(), location.size());
		memcpy(buffer + path_length, postfix.data(), postfix.size());

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
			if (kernel::params().user.storage.logging)
				VI_ERR("wal append error: %s (location: %.*s)", status.error().what(), (int)address.size(), address.data());

			return result;
		}

		if (!result->query(index_storage_configuration(kernel::params().user.storage.optimization, kernel::params().user.storage.index_page_size, kernel::params().user.storage.index_cache_size)))
			return result;

		if (initializer)
			initializer(*result);

		if (kernel::params().user.storage.logging)
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
			if (kernel::params().user.storage.logging)
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
			if (kernel::params().user.storage.logging)
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

	string keystate::init(const std::string_view& maybe_data, bool encrypted)
	{
		VI_PANIC(maybe_data.empty() || maybe_data.size() == KEY_SIZE + 32, "base keystate must be either empty or unencrypted")
		auto entropy = maybe_data.empty() ? *crypto::random_bytes(KEY_SIZE) : string(maybe_data.substr(0, KEY_SIZE));
		auto commitment = *crypto::hash(digests::sha256(), entropy);
		VI_PANIC(maybe_data.empty() || commitment == maybe_data.substr(maybe_data.size() - 32), "base keystate checksum validation failed");
		if (encrypted)
		{
			string password;
			auto* terminal = console::get();
			terminal->write("keystate password requires high initial entropy");
			terminal->fwrite("%s keystate password: ", maybe_data.empty() ? "new" : "attach");
			terminal->echo_off([&]() { password = terminal->read(1024); });
			terminal->write("verify keystate password: ");
			terminal->echo_off([&]() { VI_PANIC(!password.empty() && terminal->read(1024) == password, "password verification failed"); });

			uint8_t encryption_key[32] = { 0 }, encryption_salt[16] = { 0 };
			bool seed_acquired = algorithm::signing::derive_seed_from_high_entropy_password((uint8_t*)password.data(), password.size(), encryption_key, sizeof(encryption_key));
			VI_PANIC(seed_acquired, "encryption key derivation failed");
			crypto::fill_random_bytes(encryption_salt, sizeof(encryption_salt)).expect("encryption salt generation failed");

			auto encryption_key_view = secret_box::view(std::string_view((char*)encryption_key, sizeof(encryption_key)));
			auto encryption_salt_view = secret_box::view(std::string_view((char*)encryption_salt, sizeof(encryption_salt)));
			entropy = crypto::encrypt(ciphers::aes_256_cbc(), entropy, encryption_key_view, encryption_salt_view).expect("keystate encryption failed");
			entropy.append(std::string_view((char*)encryption_salt, sizeof(encryption_salt)));
		}
		entropy.append(commitment);
		return entropy;
	}
	void keystate::use(network_type type, const std::string_view& data, bool encrypted)
	{
		VI_PANIC(encrypted ? data.size() >= KEY_SIZE + 48 : (data.size() == KEY_SIZE + 32), "invalid keystate size");
		auto calculate = [&](const std::string_view& entropy)
		{
			string blob = to_string((uint8_t)type).append(entropy);
			for (size_t i = 0; i < entropy.size(); i++)
				blob = *crypto::hash(digests::sha256(), blob);
			key = secret_box::secure(blob);
		};
		if (encrypted)
		{
			auto password = os::process::get_env("XBASE");
			if (!password)
			{
				auto* terminal = console::get();
				terminal->write("keystate password: ");
				terminal->echo_off([&]() { password = terminal->read(1024); });
			}

			uint8_t encryption_key[32] = { 0 };
			bool seed_acquired = algorithm::signing::derive_seed_from_high_entropy_password((uint8_t*)password->data(), password->size(), encryption_key, sizeof(encryption_key));
			VI_PANIC(seed_acquired, "decryption key derivation failed");

			auto encryption_key_view = secret_box::view(std::string_view((char*)encryption_key, sizeof(encryption_key)));
			auto encryption_salt_view = secret_box::view(data.substr(data.size() - 48, 16));
			auto entropy = crypto::decrypt(ciphers::aes_256_cbc(), data.substr(0, data.size() - 48), encryption_key_view, encryption_salt_view).expect("keystate decryption failed");
			bool checksum_match = *crypto::hash(digests::sha256(), entropy) == data.substr(data.size() - 32);

			VI_PANIC(checksum_match, "keystate checksum validation failed");
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

		auto& message = kernel::params().message;
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

	void kernel::log_state::output(const std::string_view& message)
	{
		if (!resource || message.empty())
			return;

		time_t archive_time = ::time(nullptr);
		umutex<std::recursive_mutex> unique(mutex);
		resource->write((uint8_t*)message.data(), message.size());
		if (message.back() != '\r' && message.back() != '\n')
			resource->write((uint8_t*)"\n", 1);

		auto* params = kernel::pparams();
		if (!params || archive_time - repack_time < (int64_t)params->user.logs.archive_repack_interval / 1000)
			return;

		auto state = os::file::get_properties(resource->virtual_name());
		size_t current_size = state ? state->size : 0;
		repack_time = archive_time;
		if (current_size <= params->user.logs.archive_size)
			return;

		string archive_path = string(resource->virtual_name());
		resource = os::file::open_archive(archive_path, params->user.logs.archive_size).or_else(nullptr);
	}

	kernel::kernel(const inline_args& environment)
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

			value = config->child("encrypted");
			if (value != nullptr && value->value.is_boolean())
				user.encrypted = value->value.as_boolean();

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

			value = config->child("discovery.proxy");
			if (value != nullptr && value->value.is_boolean())
				user.discovery.proxy = value->value.as_boolean();

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

			value = config->child("rpc.username");
			if (value != nullptr && value->value.is_string())
				user.rpc.username = value->value.as_blob();

			value = config->child("rpc.password");
			if (value != nullptr && value->value.is_string())
				user.rpc.password = value->value.as_blob();

			value = config->child("rpc.sandbox");
			if (value != nullptr && value->value.is_boolean())
				user.rpc.sandbox = value->value.as_boolean();

			value = config->child("rpc.proxy");
			if (value != nullptr && value->value.is_boolean())
				user.rpc.proxy = value->value.as_boolean();

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
				info_log.resource = os::file::open_archive(log_path, user.logs.archive_size).or_else(nullptr);
		}

		if (!user.logs.error_path.empty())
		{
			auto log_base = database_path + user.logs.error_path;
			auto log_path = os::path::resolve(os::path::resolve(log_base, *library, true).or_else(user.logs.error_path)).or_else(user.logs.error_path);
			stringify::eval_envs(log_path, os::path::get_directory(log_path), vitex::network::utils::get_host_ip_addresses());
			os::directory::patch(os::path::get_directory(log_path));
			if (!log_path.empty())
				error_log.resource = os::file::open_archive(log_path, user.logs.archive_size).or_else(nullptr);
		}

		if (!user.logs.query_path.empty())
		{
			auto log_base = database_path + user.logs.query_path;
			auto log_path = os::path::resolve(os::path::resolve(log_base, *library, true).or_else(user.logs.query_path)).or_else(user.logs.query_path);
			stringify::eval_envs(log_path, os::path::get_directory(log_path), vitex::network::utils::get_host_ip_addresses());
			os::directory::patch(os::path::get_directory(log_path));
			if (!log_path.empty())
			{
				query_log.resource = os::file::open_archive(log_path, user.logs.archive_size).or_else(nullptr);
				if (query_log.resource)
					sqlite::driver::get()->set_query_log([this](const std::string_view& data) { query_log.output(data); });
			}
		}

		if (info_log.resource || error_log.resource)
		{
			error_handling::set_callback([this](error_handling::details& data)
			{
				if (data.type.level == log_level::error || data.type.level == log_level::warning || data.type.fatal)
				{
					if (error_log.resource)
						error_log.output(error_handling::get_message_text(data));
				}
				else if (info_log.resource)
					info_log.output(error_handling::get_message_text(data));
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
				keystate_file = box.init(*os::file::read_as_string(*os::path::resolve(value->value.as_string(), user.storage.path, true)), user.encrypted);
			else
				keystate_file = box.init(std::string_view(), user.encrypted);

			VI_PANIC(location(keystate_path).protocol == "file", "cannot save keystate into %s", keystate_path.c_str());
			os::directory::patch(os::path::get_directory(keystate_path)).expect("cannot save keystate into " + keystate_path);
			os::file::write(keystate_path, (uint8_t*)keystate_file->data(), keystate_file->size()).expect("cannot save keystate into " + keystate_path);
		}

		instance = this;
		box.use(user.network, *keystate_file, user.encrypted);
		switch (user.network)
		{
			case tangent::network_type::regtest:
			{
				uint8_t pow_root[256] = { 0xb4, 0x8a, 0xab, 0x29, 0x4a, 0xf5, 0x93, 0x0, 0x95, 0xfb, 0x31, 0x2, 0xe6, 0xe8, 0xbe, 0xae, 0xdd, 0x8e, 0xa7, 0x89, 0xce, 0xa3, 0x75, 0xf5, 0xdc, 0x2b, 0xa, 0x38, 0x2b, 0x28, 0x60, 0x3a, 0x80, 0x1, 0xb9, 0x6c, 0xed, 0xf2, 0xb7, 0x58, 0x25, 0x8, 0x68, 0x64, 0xa, 0x4d, 0x66, 0xe3, 0x6, 0xfb, 0xa9, 0x30, 0x92, 0x2, 0x29, 0xa7, 0x7c, 0x5b, 0x3a, 0xd0, 0x18, 0x63, 0x2a, 0xac, 0xdf, 0x40, 0x6a, 0xf2, 0xf6, 0x77, 0xea, 0xa2, 0x28, 0x75, 0x15, 0xc, 0x75, 0x4a, 0x3c, 0xee, 0xcb, 0x5b, 0x79, 0xe5, 0x78, 0xb0, 0x7c, 0xde, 0x75, 0x8d, 0x66, 0x4f, 0xf, 0x65, 0x1e, 0x5f, 0x97, 0x2b, 0xf8, 0x46, 0xc8, 0x42, 0xd3, 0xb9, 0x92, 0x5a, 0x94, 0x30, 0xe6, 0x2f, 0x19, 0x71, 0xb8, 0x62, 0x33, 0xc, 0xf6, 0xba, 0x81, 0x69, 0xb0, 0x24, 0xfa, 0x83, 0xc, 0x75, 0x19, 0xa0, 0xb, 0x86, 0xda, 0xe6, 0x5e, 0xfa, 0xc9, 0x16, 0x74, 0x56, 0x5, 0x9a, 0xa8, 0x13, 0x7d, 0x48, 0xaf, 0xa7, 0xc0, 0x76, 0x49, 0x33, 0x30, 0xb6, 0x65, 0x39, 0x2e, 0x5c, 0xe8, 0x4e, 0x9c, 0x6d, 0xe, 0x85, 0xbf, 0x71, 0x6a, 0x9f, 0xe2, 0xd0, 0x74, 0xaf, 0x14, 0x13, 0x52, 0x68, 0xff, 0xe9, 0xb8, 0xb5, 0xdb, 0xbd, 0x23, 0xa6, 0x14, 0x18, 0xc5, 0x27, 0x99, 0x4a, 0xf, 0x66, 0xaf, 0x7e, 0x16, 0xa0, 0xea, 0xab, 0xb3, 0xa5, 0x6a, 0xb, 0x5e, 0x6e, 0x6, 0xd9, 0xa, 0x4, 0xef, 0x3f, 0x3, 0x9b, 0x82, 0x9c, 0x5b, 0x36, 0x42, 0x18, 0x50, 0x87, 0x8d, 0x5f, 0xa9, 0x9, 0x8b, 0xb1, 0x8a, 0x23, 0xaa, 0x0, 0xf4, 0x2b, 0x11, 0xbf, 0x83, 0x72, 0xbb, 0x27, 0x46, 0x83, 0x1c, 0x64, 0x99, 0x94, 0xa6, 0xcc, 0x65, 0x88, 0xad, 0xcc, 0xa3, 0x7b, 0x23, 0xa, 0x6c, 0x7c, 0xe8, 0x85 };
				uint8_t participation_root[64] = { 0x56, 0x6, 0xb6, 0x60, 0xd1, 0xa2, 0x31, 0xb6, 0xc2, 0x46, 0x71, 0xda, 0x42, 0xa0, 0xc9, 0xa0, 0xfa, 0xd6, 0x2, 0xb1, 0xd7, 0x71, 0xf4, 0x3e, 0xc, 0x19, 0x27, 0x29, 0x93, 0x8c, 0x97, 0x12, 0x1, 0xf8, 0x1b, 0x31, 0x1e, 0xad, 0xab, 0x34, 0x17, 0xcb, 0x5d, 0x45, 0xad, 0x55, 0xf8, 0x9d, 0x74, 0xf6, 0x94, 0x6f, 0x3d, 0x3d, 0xad, 0x45, 0x45, 0x9a, 0xf3, 0x7e, 0x8e, 0xf7, 0x2, 0x9b };
				memcpy(policy.pow.root, pow_root, sizeof(pow_root));
				memcpy(policy.participation.root, participation_root, sizeof(participation_root));
				policy.pow.time = 1;
				policy.pow.difficulty = 1;
				policy.pow.security = 64;
				policy.pow.tx.difficulty = 1;
				policy.attestation.confirmation_time = 2;
				policy.attestation.min_stake_value = decimal::zero();
				policy.attestation.min_per_transaction = 0;
				policy.participation.locking_time = 2;
				policy.participation.min_stake_value = decimal::zero();
				policy.production.min_network_congestion = 2000000;
				policy.production.min_stake_value = decimal::zero();
				message.packet_magic = 0xe249c307;
				account.secret_key_prefix = "secrt";
				account.public_key_prefix = "pubrt";
				account.address_prefix = "tcrt";
				account.secret_key_version = 0xD;
				account.public_key_version = 0xC;
				account.address_version = 0x6;
				break;
			}
			case tangent::network_type::testnet:
			{
				uint8_t pow_root[256] = { 0x86, 0x7d, 0x74, 0x20, 0x38, 0xb6, 0x8c, 0x6f, 0xd, 0x8c, 0x12, 0x12, 0x85, 0x90, 0x81, 0x77, 0xf7, 0x70, 0x4, 0x75, 0x3f, 0x8c, 0xf, 0x2d, 0xa3, 0x75, 0x2d, 0x9c, 0x2, 0x71, 0x43, 0x64, 0x78, 0xa3, 0x60, 0x50, 0xe7, 0xe6, 0xa1, 0x3b, 0x67, 0x66, 0x5a, 0x1b, 0x43, 0x52, 0xb1, 0x38, 0x3b, 0xbd, 0x91, 0x15, 0xe0, 0xe1, 0x65, 0xc4, 0xeb, 0x7f, 0x85, 0x9b, 0x24, 0xf2, 0xfd, 0x3a, 0x8d, 0xa2, 0x58, 0xb0, 0x9b, 0xd, 0x88, 0xc7, 0xaa, 0xfa, 0xbf, 0x7, 0xc2, 0x6f, 0xcb, 0xce, 0x58, 0x49, 0x9c, 0xc, 0x9c, 0x2f, 0x6f, 0x39, 0x65, 0x9b, 0x69, 0x42, 0x5, 0x9e, 0x22, 0xa6, 0xf6, 0x60, 0x6f, 0x6f, 0x6a, 0xbc, 0xf9, 0x91, 0xb8, 0x37, 0xe3, 0x2a, 0x3f, 0x3d, 0x86, 0x29, 0x13, 0xa1, 0xb9, 0x82, 0x63, 0xeb, 0x2c, 0xfb, 0xbe, 0xe6, 0xb, 0xd0, 0x84, 0x67, 0xe0, 0x71, 0x5e, 0x22, 0xc3, 0xb8, 0xee, 0x2c, 0x15, 0x81, 0x72, 0xb7, 0x43, 0x10, 0xb6, 0xef, 0xd8, 0xc8, 0x41, 0x81, 0x78, 0x60, 0x32, 0xed, 0x59, 0x50, 0xe1, 0x91, 0x5f, 0xc9, 0xdd, 0x65, 0x47, 0xeb, 0xb3, 0x64, 0xb6, 0x80, 0xba, 0x4e, 0x3, 0xc4, 0x3c, 0x70, 0x9f, 0xb9, 0x9a, 0x7b, 0x83, 0x8a, 0xbf, 0x70, 0x15, 0xaf, 0xd2, 0xca, 0x7a, 0xc3, 0x58, 0x9f, 0xe4, 0xc5, 0xfc, 0x3, 0xfd, 0x49, 0x48, 0x83, 0x64, 0x1d, 0xb7, 0x89, 0xa0, 0xb5, 0x17, 0x17, 0x72, 0xc7, 0x89, 0x2e, 0xe0, 0xab, 0x6f, 0xc0, 0x61, 0x5, 0x4a, 0x8f, 0xfb, 0xb9, 0xdc, 0x57, 0x62, 0x8f, 0x60, 0x69, 0x29, 0xe4, 0x2f, 0x79, 0xc2, 0xae, 0xbe, 0xf0, 0x80, 0xd1, 0x97, 0xa3, 0x1, 0x5f, 0xa7, 0x8d, 0x51, 0x80, 0xd, 0xf, 0x1c, 0x21, 0x6d, 0xe0, 0xb3, 0xdf, 0xb3, 0x83, 0x61, 0xdd, 0xc8, 0xa1, 0xb1, 0x39 };
				uint8_t participation_root[64] = { 0x13, 0xc6, 0xe1, 0x58, 0xfd, 0x95, 0xc9, 0xe0, 0xfb, 0x5f, 0x61, 0xb2, 0x1c, 0xd3, 0x6f, 0x3b, 0xe9, 0xb2, 0x6, 0x66, 0x9c, 0xa0, 0xd6, 0xbf, 0x19, 0x44, 0x92, 0x67, 0xde, 0x4e, 0x24, 0x3c, 0x3b, 0xa6, 0x7d, 0x6f, 0x37, 0xd9, 0x26, 0x34, 0xcd, 0xb, 0x12, 0xea, 0x9, 0x4d, 0x2c, 0x63, 0xd9, 0x78, 0xa9, 0xa8, 0x57, 0x69, 0x1d, 0xb6, 0x57, 0x6a, 0x81, 0xff, 0x90, 0xdd, 0xeb, 0xff };
				memcpy(policy.pow.root, pow_root, sizeof(pow_root));
				memcpy(policy.participation.root, participation_root, sizeof(participation_root));
				message.packet_magic = 0xf815c95c;
				account.secret_key_prefix = "sect";
				account.public_key_prefix = "pubt";
				account.address_prefix = "tct";
				account.secret_key_version = 0xE;
				account.public_key_version = 0xD;
				account.address_version = 0x5;
				break;
			}
			case tangent::network_type::mainnet:
			{
				uint8_t pow_root[256] = { 0x7e, 0xdc, 0x14, 0x38, 0xcb, 0xeb, 0xea, 0x61, 0x51, 0x2d, 0xee, 0xa0, 0xc4, 0x54, 0x2f, 0xe8, 0xdc, 0x8c, 0xb1, 0x32, 0xe, 0xe2, 0x49, 0x7e, 0xa7, 0x99, 0x58, 0xa6, 0x74, 0x42, 0x5f, 0xfe, 0x4c, 0x83, 0xb1, 0x78, 0xd0, 0x9c, 0x0, 0xf5, 0x56, 0xac, 0xd5, 0x7c, 0x52, 0x52, 0x28, 0x41, 0xd1, 0xbd, 0xda, 0x49, 0xce, 0x5b, 0xe4, 0x2e, 0x87, 0x7, 0x1e, 0x4d, 0x38, 0xa2, 0xf, 0x6d, 0xf1, 0x18, 0xc6, 0x4b, 0x4d, 0xac, 0x1d, 0x5e, 0x42, 0xbb, 0x11, 0x75, 0xe1, 0x38, 0xf6, 0xfd, 0x99, 0x8a, 0x3a, 0xc3, 0x1f, 0xc5, 0x89, 0xd9, 0x17, 0xc7, 0x88, 0x92, 0x55, 0x70, 0x61, 0xf1, 0xbe, 0x24, 0x33, 0x47, 0x32, 0xfb, 0x95, 0xa4, 0x98, 0x49, 0x5, 0xcc, 0x17, 0x8b, 0xe0, 0x5b, 0x9e, 0xeb, 0xb9, 0xe1, 0xab, 0x9, 0x9f, 0x1c, 0xa7, 0xe7, 0x80, 0x35, 0xb7, 0xe9, 0xb4, 0xa3, 0xfd, 0x14, 0x84, 0xb4, 0xa9, 0xd, 0x7c, 0x6c, 0xdf, 0x33, 0x6f, 0x10, 0x89, 0x8d, 0xd2, 0x99, 0x5b, 0x80, 0x2e, 0xbf, 0xdf, 0xaa, 0x49, 0x9f, 0x5f, 0x54, 0x17, 0x83, 0x5d, 0xb2, 0xc, 0xc6, 0x86, 0x3c, 0xed, 0xbd, 0x96, 0x70, 0xb2, 0x5, 0x6d, 0x27, 0xdb, 0x75, 0x95, 0x71, 0xcb, 0x1e, 0xb9, 0xf4, 0x11, 0xc, 0x9f, 0x24, 0xcb, 0x20, 0x8, 0x19, 0x46, 0xe9, 0x82, 0x3d, 0xe5, 0x5b, 0xec, 0xe5, 0x19, 0xe, 0xd1, 0x22, 0x6b, 0xc6, 0x39, 0x61, 0xb2, 0x33, 0x25, 0x64, 0xac, 0xf1, 0x83, 0xdd, 0xcd, 0xf8, 0x65, 0xf9, 0x3, 0x2e, 0x19, 0x60, 0x8e, 0x37, 0x60, 0xad, 0xa0, 0x23, 0xbd, 0x4c, 0x6d, 0xe8, 0xd9, 0xa0, 0xba, 0x5c, 0x27, 0x10, 0xb6, 0xe0, 0x30, 0xea, 0x36, 0xc1, 0x8f, 0xe7, 0x34, 0x2, 0x7c, 0x37, 0x1a, 0x2c, 0xd8, 0x14, 0xb3, 0x9d, 0xb8, 0x47, 0x73, 0x79 };
				uint8_t participation_root[64] = { 0x83, 0xe0, 0xbd, 0x24, 0xdc, 0x6b, 0xe, 0xe3, 0x20, 0x6a, 0xa7, 0xd8, 0xae, 0xbe, 0xb7, 0x13, 0x4f, 0x50, 0x53, 0x41, 0xd4, 0x3b, 0x5c, 0x83, 0x20, 0xd8, 0x25, 0x8e, 0xb9, 0x8a, 0xb9, 0x6b, 0x48, 0xb2, 0x17, 0x42, 0xe0, 0xdf, 0xb2, 0x4d, 0x22, 0x7b, 0x24, 0x7d, 0x5, 0x6f, 0x99, 0xd6, 0x3e, 0x2b, 0x1b, 0xb, 0xa3, 0x13, 0x23, 0xb3, 0xdc, 0x39, 0x59, 0x50, 0xe7, 0x3e, 0xa9, 0x9e };
				memcpy(policy.pow.root, pow_root, sizeof(pow_root));
				memcpy(policy.participation.root, participation_root, sizeof(participation_root));
				break;
			}
			default:
				VI_PANIC(false, "bad network type");
				break;
		}

		uplinks::link_instance();
		algorithm::signing::initialize();
		algorithm::composition::initialize_cache();
	}
	kernel::~kernel()
	{
		database.checkpoint();
		superchain::bridge::cleanup_instance();
		script::factory::cleanup_instance();
		format::tree_pool::cleanup_instance();
		algorithm::composition::deinitialize_cache();
		algorithm::signing::deinitialize();
		error_handling::set_callback(nullptr);
		if (instance == this)
			instance = nullptr;
	}
	bool kernel::is(network_type type) const
	{
		return user.network == type;
	}
	bool kernel::on(fork_id fork, uint64_t block_number) const
	{
		if (user.network != network_type::mainnet)
			return true;

		return block_number >= (uint64_t)fork;
	}
	bool kernel::custom() const
	{
		return !path.empty();
	}
	const kernel& kernel::params()
	{
		VI_ASSERT(instance != nullptr, "chain parameters are not set!");
		return *instance;
	}
	const kernel* kernel::pparams()
	{
		return instance;
	}
	kernel& kernel::mparams()
	{
		VI_ASSERT(instance != nullptr, "chain parameters are not set!");
		return *instance;
	}
	kernel* kernel::instance = nullptr;
}
