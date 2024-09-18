#ifndef TAN_KERNEL_CHAIN_H
#define TAN_KERNEL_CHAIN_H
#define TAN_CONFIG_PATH "./node.json"
#define TAN_VECTORSTATE_PATH "./vectorstate.bsk"
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
using namespace Vitex::Scripting;

namespace Tangent
{
    template <typename K, typename Comparator = typename std::set<K>::key_compare>
    using OrderedSet = std::set<K, Comparator, typename AllocationType<typename std::set<K>::value_type>::type>;

    enum
    {
        MAJOR_VERSION = 1,
        MINOR_VERSION = 0,
        PATCH_VERSION = 0,
        VERSION = (MAJOR_VERSION) * 100000000 + (MINOR_VERSION) * 1000000 + (PATCH_VERSION) * 1000
    };

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

    public:
        enum
        {
            NEW_EPOCH = (size_t) - 1
        };

    private:
        UnorderedMap<String, SingleQueue<UPtr<LDB::Connection>>> Queues;
        UnorderedMap<String, size_t> Epoches;
        std::mutex Mutex;
        String TargetPath;

    public:
        UPtr<LDB::Connection> Use(size_t Epoch, const std::string_view& Location, std::function<void(LDB::Connection*)>&& Initializer);
        void Free(UPtr<LDB::Connection>&& Connection);
        void Reset();
        void Checkpoint();
        String AddressOf(size_t Epoch, const std::string_view& Location) const;
        String PathOf(size_t Epoch, const std::string_view& Location) const;
        String PartitionOf(size_t Epoch, const std::string_view& Location) const;
        size_t EpochOf(const std::string_view& Location);
        const String& Resolve(NetworkType Type, const std::string_view& Path);
        const String Location() const;

    private:
        void Restore(const std::string_view& Path);
    };

    class Timepoint
    {
    private:
        UnorderedMap<String, int64_t> Offsets;
        int64_t MillisecondsOffset = 0;
        std::mutex Mutex;

    public:
        String Adjust(const String& Source, int64_t MillisecondsDelta);
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
        struct UserDynamicConfig
        {
            struct
            {
                String NodeAddress = "0.0.0.0";
                const uint16_t NodePort = 3288;
                uint64_t NodeTimeout = 10000;
                uint64_t NodeTimeOffset = 300000;
                uint64_t TlsTrustedPeers = 0;
                uint64_t TlsValidityDays = 0;
                uint64_t CursorSize = 2048;
                uint32_t MaxInboundConnections = 32;
                uint32_t MaxOutboundConnections = 8;
                bool Proposer = true;
                bool Server = true;
            } P2P;
            struct
            {
                String NodeAddress = "0.0.0.0";
                const uint16_t NodePort = 8823;
                String AdminUsername;
                String AdminPassword;
                String UserUsername;
                String UserPassword;
                uint64_t CursorSize = 512;
                uint64_t PageSize = 64;
                bool Server = false;
            } RPC;
            struct
            {
                String Directory = "./";
                StorageOptimization Optimization = StorageOptimization::Speed;
                uint64_t CheckpointSize = 14400;
                uint64_t LocationCacheSize = 500000;
                uint64_t ScriptCacheSize = 8192;
                uint64_t PartitionSize = 68719476736llu;
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
                bool Observer = false;
            } Oracle;
            UnorderedSet<String> Seeds;
            NetworkType Network = NetworkType::Mainnet;
            String Vectorstate = TAN_VECTORSTATE_PATH;
        } User;
        struct ProtocolMessagingConfig
        {
            uint32_t MaxDataVersion = 0x10;
            uint32_t MinDataVersion = 0x10;
            uint32_t PacketVersion = 0x73d308e9;
            uint32_t MaxMessageSize = 0xffffff;
            uint32_t MaxBodySize = 1024 * 1024 * 32;
            uint32_t Precision = 18;
        } Message;
        struct ProtocolAccountConfig
        {
            String PrivateKeyPrefix = "prv";
            String PublicKeyPrefix = "pub";
            String AddressPrefix = "tan";
            String SealingPrivateKeyPrefix = "sprv";
            String SealingPublicKeyPrefix = "spub";
            uint64_t RootAddressIndex = 0;
            uint8_t PrivateKeyVersion = 0xF;
            uint8_t PublicKeyVersion = 0xE;
            uint8_t AddressVersion = 0x4;
            uint8_t SealingPrivateKeyVersion = 0xD;
            uint8_t SealingPublicKeyVersion = 0xC;
        } Account;
        struct ProtocolPolicyConfig
        {
            uint64_t ConsensusCommitteeLimit = 24;
            uint64_t ConsensusPriorityLimit = 6;
            uint64_t ConsensusProofTime = 6000;
            uint64_t ConsensusAdjustmentTime = 3600000;
            uint64_t ConsensusPenaltyPointTime = 600000;
            uint64_t TransactionThroughput = 410;
            double MaxConsensusDifficultyIncrease = 0.25;
            double MaxConsensusDifficultyDecrease = 0.75;
            double CumulativeConsensusRequired = 0.75;
            double AccountGasWorkRequired = 1000.0;
            double AccountContributionRequired = 1.0;
            double AccountRewardMaxIncrease = 0.05;
            double WeightMultiplier = 10000.0;
        } Policy;

    private:
        String Path;

    public:
        Repository Database;
        Vectorstate Key;
        Timepoint Time;

    public:
        Protocol(const std::string_view& Path = TAN_CONFIG_PATH);
        virtual ~Protocol();
        bool Is(NetworkType Type) const;

    public:
        static Protocol& Change();
        static const Protocol& Now();
    };
}
#endif