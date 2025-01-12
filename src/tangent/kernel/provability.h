#ifndef TAN_KERNEL_PROVABILITY_H
#define TAN_KERNEL_PROVABILITY_H
#include "../policy/messages.h"

namespace Tangent
{
	namespace Provability
	{
        typedef uint256_t(*HashFunction)(const uint256_t&, const uint256_t&);

        class Util
        {
        public:
            static uint256_t Sha256ci(const uint256_t& A, const uint256_t& B);
            static uint64_t Sha64d(const uint8_t* Buffer, size_t Size);
            static uint64_t Sha64d(const std::string_view& Buffer);
        };

		struct MerkleTree
		{
        public:
            struct Path
            {
                friend MerkleTree;

            private:
                Vector<uint256_t> Nodes;
                size_t Index = 0;

            public:
                HashFunction Hasher = &Util::Sha256ci;

            public:
                uint256_t CalculateRoot(uint256_t Hash) const;
                Vector<uint256_t>& GetBranch();
                const Vector<uint256_t>& GetBranch() const;
                size_t GetIndex() const;
                bool Empty();
            };

        private:
            Vector<uint256_t> Nodes;
            size_t Hashes = 0;

        public:
            HashFunction Hasher = &Util::Sha256ci;

        public:
            MerkleTree();
            MerkleTree(const uint256_t& PrevMerkleRoot);
            MerkleTree(const MerkleTree&) = default;
            MerkleTree(MerkleTree&&) = default;
            MerkleTree& operator=(const MerkleTree&) = default;
            MerkleTree& operator=(MerkleTree&&) = default;
            MerkleTree& Shift(const uint256_t& Hash);
            MerkleTree& Push(const uint256_t& Hash);
            MerkleTree& Reset();
            MerkleTree& Calculate();
            Path CalculatePath(const uint256_t& Hash);
            uint256_t CalculateRoot();
            const Vector<uint256_t>& GetTree();
            const Vector<uint256_t>& GetTree() const;
            size_t GetComplexity() const;
            bool IsCalculated() const;
		};

        template <typename T>
        struct MerkleArray
        {
            static_assert(std::is_base_of<Messages::Generic, T>::value || std::is_base_of<Messages::Authentic, T>::value, "type should be derived from message type");

        private:
            MerkleTree Tree;
            Vector<T> Array;

        public:
            MerkleArray(HashFunction Hasher = &Util::Sha256ci)
            {
                Tree.Hasher = Hasher;
            }
            MerkleArray(const uint256_t& PrevMerkleRoot, HashFunction Hasher = &Util::Sha256ci) : Tree(PrevMerkleRoot)
            {
                Tree.Hasher = Hasher;
            }
            MerkleArray(const MerkleArray&) = default;
            MerkleArray(MerkleArray&&) = default;
            MerkleArray& operator=(const MerkleArray&) = default;
            MerkleArray& operator=(MerkleArray&&) = default;
            T& Shift(const T& Value)
            {
                Array.emplace(Array.begin(), Value);
                Tree.Shift(Value.AsHash());
                return Array.back();
            }
            T& Shift(const T& Value, const uint256_t& PrecomputedHash)
            {
                VI_ASSERT(PrecomputedHash == Value.AsHash(), "invalid precomputed hash");
                Array.emplace(Array.begin(), Value);
                Tree.Shift(PrecomputedHash);
                return Array.back();
            }
            T& Shift(T&& Value)
            {
                Array.emplace(Array.begin(), std::move(Value));
                Tree.Shift(Value.AsHash());
                return Array.back();
            }
            T& Shift(T&& Value, const uint256_t& PrecomputedHash)
            {
                VI_ASSERT(PrecomputedHash == Value.AsHash(), "invalid precomputed hash");
                Array.emplace(Array.begin(), std::move(Value));
                Tree.Shift(PrecomputedHash);
                return Array.back();
            }
            T& Push(const T& Value)
            {
                Array.emplace_back(Value);
                Tree.Push(Value.AsHash());
                return Array.back();
            }
            T& Push(const T& Value, const uint256_t& PrecomputedHash)
            {
                VI_ASSERT(PrecomputedHash == Value.AsHash(), "invalid precomputed hash");
                Array.emplace_back(Value);
                Tree.Push(PrecomputedHash);
                return Array.back();
            }
            T& Push(T&& Value)
            {
                Array.emplace_back(std::move(Value));
                Tree.Push(Value.AsHash());
                return Array.back();
            }
            T& Push(T&& Value, const uint256_t& PrecomputedHash)
            {
                VI_ASSERT(PrecomputedHash == Value.AsHash(), "invalid precomputed hash");
                Array.emplace_back(std::move(Value));
                Tree.Push(PrecomputedHash);
                return Array.back();
            }
            MerkleArray& Reset()
            {
                Array.clear();
                Tree.Reset();
                return *this;
            }
            MerkleArray& Calculate()
            {
                Tree.Calculate();
                return *this;
            }
            MerkleTree::Path CalculatePath(const uint256_t& Hash)
            {
                return Tree.CalculatePath(Hash);
            }
            uint256_t CalculateRoot()
            {
                return Tree.CalculateRoot();
            }
            const Vector<uint256_t>& GetTree()
            {
                return Tree.GetTree();
            }
            const Vector<T>& GetArray() const
            {
                return Array;
            }
            size_t GetComplexity() const
            {
                return Tree.GetComplexity();
            }
            bool IsCalculated() const
            {
                return Tree.IsCalculated();
            }

        public:
            Vector<T>::iterator begin()
            {
                return Array.begin();
            }
            Vector<T>::const_iterator begin() const
            {
                return Array.begin();
            }
            Vector<T>::iterator end()
            {
                return Array.end();
            }
            Vector<T>::const_iterator end() const
            {
                return Array.end();
            }
        };

        class WesolowskiVDF
        {
        public:
            typedef String Digest;

        public:
            struct Parameters
            {
                uint32_t Length = 512;
                uint32_t Bits = 256;
                uint64_t Pow = 131072;

                uint128_t Difficulty() const;
            };

            struct Distribution
            {
                String Signature;
                uint256_t Value = 0;
                uint256_t Nonce = 0;

                uint256_t Derive();
                uint256_t Derive(const uint256_t& Step) const;
            };

        private:
            static Parameters DefaultAlg;

        public:
            static Distribution Random(const Parameters& Alg, const Format::Stream& Seed);
            static Parameters Calibrate(uint64_t Confidence);
            static Parameters Adjust(const Parameters& PrevAlg, uint64_t PrevTime, uint64_t TargetIndex);
            static Parameters Bump(const Parameters& Alg, double Bump);
            static String Evaluate(const Parameters& Alg, const std::string_view& Message);
            static bool Verify(const Parameters& Alg, const std::string_view& Message, const String& Sig);
            static int8_t Compare(const String& Sig1, const String& Sig2);
            static uint64_t Locktime(const String& Sig);
            static uint64_t AdjustmentInterval();
            static uint64_t AdjustmentIndex(uint64_t Index);
            static void SetDefault(const Parameters& Alg);
            static const Parameters& GetDefault();
        };

        class NakamotoPOW
        {
        public:
            static uint256_t Evaluate(const uint256_t& Nonce, const std::string_view& Message);
            static bool Verify(const uint256_t& Nonce, const std::string_view& Message, const uint256_t& Target, const uint256_t& Solution);
            static void Serialize(Format::Stream& Stream, const uint256_t& Nonce, const std::string_view& Message);
        };
	}
}
#endif