#ifndef TAN_KERNEL_CHAIN_H
#define TAN_KERNEL_CHAIN_H
#define TAN_CONFIG_PATH "./node.json"
#include <vitex/compute.h>
#include <vitex/layer.h>
#include <vitex/scripting.h>
#include <vitex/network/http.h>
#include <vitex/network/ldb.h>
#include <vitex/vitex.h>
#include <set>

using namespace Vitex::Core;
using namespace Vitex::Compute;
using namespace Vitex::Layer;
using namespace Vitex::Network;

namespace rocksdb
{
    class DB;
}

namespace Tangent
{
    template <typename K, typename Comparator = typename std::set<K>::key_compare>
    using OrderedSet = std::set<K, Comparator, typename AllocationType<typename std::set<K>::value_type>::type>;

    enum class NetworkType
    {
        Regtest,
        Testnet,
        Mainnet
    };

    enum class StorageOptimization
    {
        Safety,
        Speed
    };

    class LayerException : public std::exception
    {
    public:
        String Info;

    public:
        LayerException();
        LayerException(String&& Text);
        const char* what() const noexcept override;
    };

    template <typename V>
    using ExpectsLR = Expects<V, LayerException>;

    template <typename V>
    using ExpectsPromiseLR = ExpectsPromise<V, LayerException>;

    class Repository
    {
        friend class Protocol;

    private:
        UnorderedMap<String, SingleQueue<UPtr<LDB::Connection>>> Indices;
        UnorderedMap<String, std::unique_ptr<rocksdb::DB>> Blobs;
        std::mutex Mutex;
        String TargetPath;

    public:
        rocksdb::DB* LoadBlob(const std::string_view& Location);
        UPtr<LDB::Connection> LoadIndex(const std::string_view& Location, std::function<void(LDB::Connection*)>&& Initializer);
        void UnloadIndex(UPtr<LDB::Connection>&& Connection);
        void Reset();
        void Checkpoint();
        const String& Resolve(NetworkType Type, const std::string_view& Path);
        const String Location() const;
    };

    class Timepoint
    {
    private:
        UnorderedMap<String, int64_t> Offsets;
        int64_t MillisecondsOffset = 0;
        std::mutex Mutex;

    public:
        String Adjust(const SocketAddress& Source, int64_t MillisecondsDelta);
        uint64_t Now() const;
        uint64_t NowCPU() const;
    };

    class Vectorstate
    {
    private:
        PrivateKey Key;

    public:
        String New();
        void Use(NetworkType Type, const std::string_view& Data);
        ExpectsLR<String> EncryptBlob(const std::string_view& Data) const;
        ExpectsLR<String> DecryptBlob(const std::string_view& Data) const;
        ExpectsLR<String> EncryptKey(const PrivateKey& Data) const;
        ExpectsLR<PrivateKey> DecryptKey(const std::string_view& Data) const;
    };

    class Protocol : public Reference<Protocol>
    {
    private:
        static Protocol* Instance;

    public:
        struct Logger
        {
            std::recursive_mutex Mutex;
            UPtr<Stream> Resource;
            int64_t RepackTime = 0;

            void Output(const std::string_view& Message);
        };

    public:
        struct UserDynamicConfig
        {
            struct
            {
                String Address = "0.0.0.0";
                uint16_t Port = 18418;
                uint64_t TimeOffset = 300000;
                uint64_t CursorSize = 2048;
                uint32_t MaxInboundConnections = 32;
                uint32_t MaxOutboundConnections = 8;
                uint32_t InventorySize = 8192;
                uint32_t InventoryTimeout = 300;
                bool Proposer = false;
                bool Server = true;
                bool Logging = true;
            } P2P;
            struct
            {
                String Address = "0.0.0.0";
                uint16_t Port = 18420;
                uint64_t CursorSize = 512;
                bool Server = false;
                bool Logging = true;
            } NDS;
            struct
            {
                String Address = "0.0.0.0";
                uint16_t Port = 18419;
                String AdminUsername;
                String AdminPassword;
                String UserUsername;
                String UserPassword;
                uint64_t CursorSize = 512;
                uint64_t PageSize = 64;
                bool Messaging = true;
                bool WebSockets = false;
                bool Server = false;
                bool Logging = true;
            } RPC;
            struct
            {
                uint64_t Timeout = 10000;
                uint64_t TlsTrustedPeers = 100;
            } TCP;
            struct
            {
                String Directory = "./";
                StorageOptimization Optimization = StorageOptimization::Speed;
                uint64_t TransactionTimeout = 86400;
                uint64_t CheckpointSize = 64;
                uint64_t LocationCacheSize = 500000;
                uint64_t ScriptCacheSize = 8192;
                uint64_t BlobCacheSize = 134217728;
                uint64_t IndexPageSize = 65536;
                int64_t IndexCacheSize = -2000;
                double FlushThreadsRatio = 0.25;
                double CompactionThreadsRatio = 0.25;
                double ComputationThreadsRatio = 0.00;
                bool PruneAggressively = false;
                bool TransactionToAccountIndex = true;
                bool TransactionToRollupIndex = true;
                bool Logging = true;
            } Storage;
            struct
            {
                uint64_t BlockReplayMultiplier = 4;
                uint64_t RelayingTimeout = 30000;
                uint64_t RelayingRetryTimeout = 300;
                uint32_t CacheShortSize = 16384;
                uint32_t CacheExtendedSize = 65536;
                uint64_t FeeEstimationSeconds = 600;
                uint64_t WithdrawalTime = 300000;
                bool Server = false;
                bool Logging = true;
            } Observer;
            struct
            {
                String State;
                String Message;
                String Data;
                uint64_t ArchiveSize = 8 * 1024 * 1024;
                uint64_t ArchiveRepackInterval = 1800;
            } Logs;
            UnorderedSet<String> Seeds;
            UnorderedSet<String> Seeders;
            NetworkType Network = NetworkType::Mainnet;
            String Vectorstate = "./vectorstate.bsk";
        } User;
        struct ProtocolMessagingConfig
        {
            uint32_t ProtocolVersion = 0x10;
            uint32_t PacketMagic = 0x73d308e9;
            uint32_t MaxMessageSize = 0xffffff;
            uint32_t MaxBodySize = 1024 * 1024 * 32;
            uint32_t Precision = 18;
        } Message;
        struct ProtocolAccountConfig
        {
            String SignedMessageMagic = "Tangent Signed Message:\n";
            String SecretKeyPrefix = "sec";
            String SealingKeyPrefix = "seal";
            String PublicKeyPrefix = "pub";
            String AddressPrefix = "tc";
            uint64_t RootAddressIndex = 0;
            uint8_t SecretKeyVersion = 0xF;
            uint8_t PublicKeyVersion = 0xE;
            uint8_t SealingKeyVersion = 0xC;
            uint8_t AddressVersion = 0x4;
        } Account;
        struct ProtocolPolicyConfig
        {
            uint64_t ConsensusCommitteeMajors = 20;
            uint64_t ConsensusCommitteeMinors = 4;
            uint64_t ConsensusCommitteeAggregators = 32;
            uint64_t ConsensusProofTime = 10000;
            uint64_t ConsensusAdjustmentTime = 3600000;
            uint64_t ConsensusPenaltyPointTime = 600000;
            uint64_t ConsensusRecoveryProofs = 12;
            uint64_t TransactionThroughput = 210;
            uint64_t ParallelDelegationLimit = 1;
            uint64_t ParallelConsensusLimit = 128;
            uint64_t ParallelAggregationLimit = 256;
            double ConsensusAggregationThreshold = 0.66;
            double ConsensusRecoveryBump = 36.0;
            double GenesisSlotTimeBump = 0.2;
            double MaxConsensusDifficultyIncrease = 0.25;
            double MaxConsensusDifficultyDecrease = 0.75;
            double AccountGasWorkRequired = 1000.0;
            double AccountContributionRequired = 1.0;
            double AccountRewardMaxIncrease = 0.05;
            double WeightMultiplier = 10000.0;
        } Policy;

    private:
        struct
        {
            Logger State;
            Logger Message;
            Logger Data;
        } Logs;
        String Path;

    public:
        Repository Database;
        Vectorstate Key;
        Timepoint Time;

    public:
        Protocol(const std::string_view& Path = TAN_CONFIG_PATH);
        virtual ~Protocol();
        bool Is(NetworkType Type) const;
        Logger& StateLog();
        Logger& MessageLog();
        Logger& DataLog();

    public:
        static bool Bound();
        static Protocol& Change();
        static const Protocol& Now();
    };
}
#endif