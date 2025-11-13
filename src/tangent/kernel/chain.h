#ifndef TAN_KERNEL_CHAIN_H
#define TAN_KERNEL_CHAIN_H
#include <vitex/compute.h>
#include <vitex/layer.h>
#include <vitex/scripting.h>
#include <vitex/network/http.h>
#include <vitex/network/sqlite.h>
#include <vitex/vitex.h>
#include <set>

namespace rocksdb
{
    class DB;
}

namespace tangent
{
    using namespace vitex::core;
    using namespace vitex::compute;
    using namespace vitex::layer;
    using namespace vitex::network;

    template <typename k, typename comparator = typename std::set<k>::key_compare>
    using ordered_set = std::set<k, comparator, typename allocation_type<typename std::set<k>::value_type>::type>;

    enum
    {
        ELEMENTS_FEW = 32,
        ELEMENTS_MANY = 512
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
        const char* what() const noexcept override;
        string&& message() noexcept;
    };

    class remote_exception : public std::exception
    {
    private:
        string error_message;
        int8_t error_status;

    public:
        remote_exception(string&& text);
        const char* what() const noexcept override;
        string&& message() noexcept;
        bool is_retry() const noexcept;
        bool is_shutdown() const noexcept;
        static remote_exception retry();
        static remote_exception shutdown();

    private:
        remote_exception(int8_t new_status);
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
        friend class protocol;

    private:
        unordered_map<string, single_queue<uref<sqlite::connection>>> indices;
        unordered_map<string, rocksdb::DB*> blobs;
        std::mutex mutex;
        string target_path;

    public:
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
        unordered_map<string, int64_t> offsets;
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
        string init();
        void use(network_type type, const std::string_view& data);
        expects_lr<string> encrypt(const std::string_view& data) const;
        expects_lr<string> decrypt(const std::string_view& data) const;
    };

    class protocol
    {
    private:
        static protocol* instance;

    public:
        struct logger
        {
            std::recursive_mutex mutex;
            uptr<stream> resource;
            int64_t repack_time = 0;

            void output(const std::string_view& message);
        };

    public:
        struct user_dynamic_config
        {
            struct
            {
                string address = "0.0.0.0";
                uint16_t port = 18418;
                uint64_t time_offset = 300000;
                uint64_t hashes_per_query = 2048;
                uint64_t headers_per_query = 256;
                uint32_t max_inbound_connections = 24;
                uint32_t max_outbound_connections = 8;
                uint64_t inventory_timeout = 300000;
                uint32_t inventory_size = 65536;
                uint32_t topology_timeout = 120000;
                uint64_t response_timeout = 48000;
                bool may_propose = true;
                bool server = true;
                bool logging = true;
            } consensus;
            struct
            {
                string address = "0.0.0.0";
                uint16_t port = 18420;
                uint64_t cursor_size = 512;
                bool external = false;
                bool server = false;
                bool logging = true;
            } discovery;
            struct
            {
                uptr<schema> options;
                uint64_t block_replay_multiplier = 4;
                uint64_t relaying_timeout = 30000;
                uint64_t relaying_retry_timeout = 300;
                uint32_t cache1_size = 32768;
                uint32_t cache2_size = 131072;
                bool server = false;
                bool logging = true;
            } oracle;
            struct
            {
                string address = "0.0.0.0";
                uint16_t port = 18419;
                string username;
                string password;
                uint64_t cursor_size = 512;
                uint64_t page_size = 64;
                bool web_sockets = false;
                bool isolated = true;
                bool external = false;
                bool server = false;
                bool logging = true;
            } rpc;
            struct
            {
                uint64_t timeout = 10000;
                uint64_t mbps_per_socket = 24;
                uint64_t tls_trusted_peers = 100;
            } tcp;
            struct
            {
                string path;
                string module_cache_path;
                storage_optimization optimization = storage_optimization::speed;
                uint64_t transaction_dispatch_repeat_interval = 600;
                uint64_t transaction_timeout = 86400;
                uint64_t commitment_timeout = 14400;
                uint64_t mempool_transaction_limit = 10000000;
                uint64_t checkpoint_size = 100;
                uint64_t location_cache_size = 500000;
                uint64_t module_cache_size = 8192;
                uint64_t blob_cache_size = 134217728;
                uint64_t index_page_size = 65536;
                int64_t index_cache_size = -2000;
                double flush_threads_ratio = 0.25;
                double compaction_threads_ratio = 0.25;
                double computation_threads_ratio = 0.00;
                bool prune_aggressively = false;
                bool transaction_to_account_index = true;
                bool transaction_to_rollup_index = true;
                bool prevent_reorganization = true;
                bool logging = false;
            } storage;
            struct
            {
                string info_path;
                string error_path;
                string query_path;
                uint64_t archive_size = 8 * 1024 * 1024;
                uint64_t archive_repack_interval = 1800;
                bool control_logging = false;
            } logs;
            unordered_set<string> known_nodes;
            unordered_set<string> bootstrap_nodes;
            network_type network = network_type::mainnet;
            string keystate;
        } user;
        struct protocol_messaging_config
        {
            uint32_t protocol_version = 0x10;
            uint32_t packet_magic = 0x73d308e9;
            uint32_t max_message_size = 0xffffff;
            uint32_t max_body_size = 1024 * 1024 * 32;
            uint32_t decimal_precision = 18;
            uint32_t integer_precision = 78;
        } message;
        struct protocol_account_config
        {
            string secret_key_prefix = "sec";
            string public_key_prefix = "pub";
            string address_prefix = "tc";
            uint64_t message_magic = 0x6a513fb6b3b71f02;
            uint8_t secret_key_version = 0xF;
            uint8_t public_key_version = 0xE;
            uint8_t address_version = 0x4;
        } account;
        struct protocol_policy_config
        {
            string token = "TAN";
            uint64_t production_max_per_block = 12;
            uint64_t participation_min_per_account = 2;
            uint64_t participation_std_per_account = 4;
            uint64_t participation_max_per_account = 16;
            uint64_t attestation_max_per_transaction = 32;
            uint64_t consensus_proof_time = 6000;
            uint64_t consensus_adjustment_time = 60000;
            uint64_t commitment_throughput = 10;
            uint64_t transaction_throughput = 200;
            uint64_t transaction_gas = 30000;
            uint64_t wesolowski_ops = 2048;
            uint64_t genesis_round_length = 14400;
            uint32_t delegations_max_per_account = 6;
            uint32_t delegations_zeroing_time = 25000;
            uint16_t wesolowski_bits = 2048;
            decimal production_reward_value = std::string_view("1.25");
            decimal production_penalty_rate = std::string_view("0.10");
            decimal participation_stake_threshold = std::string_view("0.20");
            decimal participation_fee_rate = std::string_view("0.30");
            decimal attestation_consensus_threshold = std::string_view("0.66");
            decimal attestation_fee_rate = std::string_view("0.15");
            decimal bridge_reward_max_increase = std::string_view("0.05");
            decimal consensus_difficulty_max_increase = std::string_view("2.00");
            decimal consensus_difficulty_max_decrease = std::string_view("0.50");
            decimal consensus_difficulty_bump_per_priority = std::string_view("1.3625");
            decimal consensus_difficulty_bump_outside_priority = std::string_view("90.0");
        } policy;

    private:
        struct
        {
            logger info;
            logger error;
            logger query;
        } logs;
        string path;

    public:
        repository database;
        keystate box;
        timepoint time;

    public:
        protocol(const inline_args& environment);
        virtual ~protocol();
        bool is(network_type type) const;
        bool custom() const;

    public:
        static bool bound();
        static protocol& change();
        static const protocol& now();
    };
}
#endif