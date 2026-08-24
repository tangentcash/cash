#ifndef TAN_KERNEL_CHAIN_H
#define TAN_KERNEL_CHAIN_H
#include <vitex/layer.h>
#include <vitex/network/sqlite.h>

namespace rocksdb
{
	class DB;
}

namespace tangent
{
	using namespace vitex::core;
	using namespace vitex::compute;
	using namespace vitex::network;
	using namespace vitex::layer;

	namespace format
	{
		struct tree;
	}

	enum
	{
		ELEMENTS_FEW = 1 << 5,
		ELEMENTS_BULK = 1 << 9,
		ELEMENTS_MANY = 1 << 12,
		ELEMENTS_HUGE = 1 << 17,
		FORK_VERSION = 6,
		PATCH_VERSION = 0
	};

	enum class fork_id
	{
		key_bind_commitment = 400000,
		key_bind_uniqueness = 840000,
		difficulty_gas_work = 890000,
		consensus_challenge = 920000,
		base_to_root_modulo = 1001000,
		attesters_hardening = 1273450
	};

	enum class network_type
	{
		regtest,
		testnet,
		mainnet
	};

	enum class storage_optimization
	{
		safety,
		speed
	};

	class layer_exception : public std::exception
	{
	private:
		string error_message;

	public:
		layer_exception();
		layer_exception(string&& text);
		layer_exception(const layer_exception& other);
		layer_exception(layer_exception&& other) noexcept;
		layer_exception& operator=(const layer_exception& other);
		layer_exception& operator=(layer_exception&& other) noexcept;
		const char* what() const noexcept override;
		string&& message() noexcept;
	};

	class remote_exception : public std::exception
	{
	private:
		string error_message;
		int8_t error_status;
		uint64_t error_retry_time;

	public:
		remote_exception();
		remote_exception(string&& text);
		remote_exception(const remote_exception& other);
		remote_exception(remote_exception&& other) noexcept;
		remote_exception& operator=(const remote_exception& other);
		remote_exception& operator=(remote_exception&& other) noexcept;
		const char* what() const noexcept override;
		string&& message() noexcept;
		uint64_t retry_after_timestamp() const noexcept;
		bool is_retry_after() const noexcept;
		bool is_retry() const noexcept;
		bool is_shutdown() const noexcept;
		static remote_exception retry_later(string&& text = string());
		static remote_exception retry_after(uint64_t timestamp, string&& text = string());
		static remote_exception shutdown(string&& text = string());

	private:
		remote_exception(string&& text, int8_t new_status, uint64_t new_retry_time);
	};

	template <typename v>
	using expects_lr = expects<v, layer_exception>;

	template <typename v>
	using expects_promise_lr = expects_promise<v, layer_exception>;

	template <typename v>
	using expects_rt = expects<v, remote_exception>;

	template <typename v>
	using expects_promise_rt = expects_promise<v, remote_exception>;

	class repository
	{
		friend class kernel;

	private:
		hash_map<string, single_queue<uref<sqlite::connection>>> indices;
		hash_map<string, rocksdb::DB*> blobs;
		std::mutex mutex;
		string target_path;

	public:
		~repository();
		rocksdb::DB* pull_blob_ref(const std::string_view& location);
		uref<sqlite::connection> pull_index(const std::string_view& location, std::function<void(sqlite::connection*)>&& initializer);
		void push_index(uref<sqlite::connection>&& connection);
		void reset();
		void checkpoint();
		const string& resolve(network_type type, const std::string_view& path);
		const string location() const;
	};

	class timepoint
	{
	private:
		hash_map<string, int64_t> offsets;
		int64_t milliseconds_offset = 0;
		std::mutex mutex;

	public:
		string adjust(const socket_address& source, int64_t milliseconds_delta);
		uint64_t now() const;
		uint64_t now_cpu() const;
	};

	class keystate
	{
	private:
		secret_box key;

	public:
		string init(const std::string_view& maybe_data, bool encrypted);
		void use(network_type type, const std::string_view& data, bool encrypted);
		expects_lr<string> encrypt(const std::string_view& data) const;
		expects_lr<string> decrypt(const std::string_view& data) const;
	};

	class kernel
	{
	public:
		struct user_config
		{
			struct
			{
				vector<string> accounts;
				string address = "0.0.0.0";
				uint16_t port = 18418;
				uint32_t max_inbound_connections = 64;
				uint32_t max_outbound_connections = 8;
				uint64_t inventory_timeout = 300000;
				uint32_t inventory_size = 32768;
				uint64_t aggregation_attempts = 6;
				uint64_t aggregation_cooldown = 2000;
				uint8_t coordination_attempts = 15;
				bool reorganizable = false;
				bool miner = true;
				bool server = true;
				bool logging = true;
			} consensus;
			struct
			{
				string address = "127.0.0.1";
				uint16_t port = 18420;
				bool proxy = false;
				bool server = false;
				bool logging = true;
			} discovery;
			struct
			{
				uptr<format::tree> options;
				uint64_t polling_frequency = 60000;
				uint32_t cache1_size = 4096;
				uint32_t cache2_size = 16384;
				bool listener = false;
				bool logging = true;
			} superchain;
			struct
			{
				string address = "127.0.0.1";
				uint16_t port = 18419;
				string username;
				string password;
				bool sandbox = true;
				bool proxy = false;
				bool server = false;
				bool logging = true;
			} rpc;
			struct
			{
				uint64_t timeout = 30000;
				uint64_t keep_alive = 5000;
				uint64_t mbps_per_socket = 72;
				uint64_t tls_trusted_peers = 100;
			} tcp;
			struct
			{
				string path;
				string module_cache_path;
				storage_optimization optimization = storage_optimization::speed;
				uint64_t checkpoint_size = 128;
				uint64_t module_cache_size = 8192;
				uint64_t blob_cache_size = 134217728;
				uint64_t index_page_size = 65536;
				int64_t index_cache_size = -2000;
				double flush_threads_ratio = 0.25;
				double compaction_threads_ratio = 0.25;
				double computation_threads_ratio = 0.00;
				bool transaction_to_account_index = true;
				bool transaction_to_alias_index = true;
				bool logging = false;
			} storage;
			struct
			{
				string info_path;
				string error_path;
				string query_path;
				uint64_t archive_size = 8 * 1024 * 1024;
				uint64_t archive_repack_interval = 1800000;
				bool control_logging = false;
			} logs;
			hash_set<string> known_nodes;
			hash_set<string> bootstrap_nodes;
			network_type network = network_type::mainnet;
			string keystate;
			bool encrypted = false;
		} user;
		struct messaging_config
		{
			uint64_t packet_magic = 0x73d308e9;
			uint32_t max_message_size = 0xffffff;
			uint32_t max_message_depth = 1024;
			uint32_t max_body_size = 1024 * 1024 * 24;
			uint32_t decimal_precision = 18;
			uint32_t integer_precision = 78;
			uint64_t hashes_per_query = 32768;
			uint64_t headers_per_query = 8192;
			uint64_t blocks_size_per_query = 1024 * 1024 * 8;
			uint64_t transactions_per_query = 32;
			uint64_t items_per_query = 512;
			uint64_t pages_per_query = 64;
			uint64_t timestamp_delta = 60000;
		} message;
		struct account_config
		{
			string secret_key_prefix = "sec";
			string public_key_prefix = "pub";
			string address_prefix = "tc";
			uint64_t message_magic = 0x6a513fb6b3b71f02;
			uint8_t secret_key_version = 0xF;
			uint8_t public_key_version = 0xE;
			uint8_t address_version = 0x4;
		} account;
		struct policy_config
		{
			struct
			{
				struct
				{
					uint64_t validity_time = 240000;
					uint32_t difficulty = 13;
					uint16_t steps = 256;
				} tx;
				uint8_t root[256];
				uint64_t time = 12000;
				uint64_t adjustment_time = 120000;
				uint64_t difficulty = 2048;
				uint16_t security = 2048;
				decimal max_increase = std::string_view("2.00");
				decimal max_decrease = std::string_view("0.50");
				decimal bump_per_priority = std::string_view("1.3625");
				decimal bump_outside_priority = std::string_view("60.0");
			} pow;
			struct
			{
				uint64_t confirmation_time = 172800000;
				uint64_t min_per_transaction = 4;
				uint64_t max_per_transaction = 32;
				decimal min_stake_value = std::string_view("900");
				decimal stake_penalty_threshold = std::string_view("0.1");
				decimal consensus_threshold = std::string_view("0.70");
				decimal fee_rate = std::string_view("0.10");
			} attestation;
			struct
			{
				uint8_t root[64];
				uint64_t locking_time = 691200000;
				uint64_t referencing_time = 1382400000;
				uint64_t min_per_account = 7;
				uint64_t max_per_account = 23;
				decimal min_stake_value = std::string_view("2700");
				decimal stake_threshold = std::string_view("0.20");
				decimal stake_penalty_threshold = std::string_view("0.15");
				decimal fee_rate = std::string_view("0.60");
			} participation;
			struct
			{
				uint64_t max_per_block = 12;
				uint256_t min_network_congestion = 250000;
				decimal min_gas_price = std::string_view("0.0000000001");
				decimal min_stake_value = std::string_view("12");
			} production;
			struct
			{
				uint64_t epoch_length = 500000;
				uint64_t genesis_epoch_length = 5000;
				decimal decay_rate = std::string_view("0.01");
				decimal genesis_coinbase_value = std::string_view("40");
				decimal coinbase_value = std::string_view("1.2");
				decimal min_coinbase_value = std::string_view("0.0002");
			} emission;
			string token = "TAN";
			uint64_t account_nonce_step_limit = 1048576;
			uint64_t block_gas_limit = 40'000'000;
			uint64_t commitments_per_block = 20;
			uint64_t zero_gas_price_size_limit = 512;
		} policy;

	private:
		struct log_state
		{
			std::recursive_mutex mutex;
			uptr<stream> resource;
			int64_t repack_time = 0;

			void output(const std::string_view& message);
		};
		static kernel* instance;
		log_state info_log;
		log_state error_log;
		log_state query_log;
		string path;

	public:
		std::mutex mutex;
		repository database;
		keystate box;
		timepoint time;

	public:
		kernel(const inline_args& environment);
		virtual ~kernel();
		bool is(network_type type) const;
		bool on(fork_id fork, uint64_t block_number) const;
		bool custom() const;
		static const kernel& params();
		static const kernel* pparams();
		static kernel& mparams();
	};
}
#endif