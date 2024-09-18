#include "provability.h"
#include <csetjmp>
#ifdef TAN_GMP
#include <gmp.h>
#endif

namespace Tangent
{
    namespace Provability
    {
#ifdef TAN_GMP
        struct GmpSignature
        {
            mpz_t P;
            mpz_t L;
            mpz_t Y;
            mpz_t N;
            uint64_t T;
        };

        static String SerializeSignature(const GmpSignature& Sig)
        {
            size_t PS = 0, LS = 0, YS = 0, NS = 0;
            char* P = (char*)mpz_export(nullptr, &PS, 1, 1, 1, 0, Sig.P);
            char* L = (char*)mpz_export(nullptr, &LS, 1, 1, 1, 0, Sig.L);
            char* Y = (char*)mpz_export(nullptr, &YS, 1, 1, 1, 0, Sig.Y);
            char* N = (char*)mpz_export(nullptr, &NS, 1, 1, 1, 0, Sig.N);
            Format::Stream Stream;
            Stream.WriteInteger(Sig.T);
            Stream.WriteString(std::string_view(P, PS));
            Stream.WriteString(std::string_view(L, LS));
            Stream.WriteString(std::string_view(Y, YS));
            Stream.WriteString(std::string_view(N, NS));
            Stream.WriteInteger(Util::Sha64d(Stream.Data));

            void (*gmp_free)(void*, size_t);
            mp_get_memory_functions(nullptr, nullptr, &gmp_free);
            gmp_free(P, PS);
            gmp_free(L, LS);
            gmp_free(Y, YS);
            gmp_free(N, NS);
            return Stream.Data;
        }
        static Option<GmpSignature> DeserializeSignature(const String& Sig)
        {
            String P, L, Y, N; uint64_t T;
            Format::Stream Stream = Format::Stream(Sig);
            if (!Stream.ReadInteger(Stream.ReadType(), &T))
                return Optional::None;

            if (!Stream.ReadString(Stream.ReadType(), &P))
                return Optional::None;

            if (!Stream.ReadString(Stream.ReadType(), &L))
                return Optional::None;

            if (!Stream.ReadString(Stream.ReadType(), &Y))
                return Optional::None;

            if (!Stream.ReadString(Stream.ReadType(), &N))
                return Optional::None;

            uint64_t Checksum, Seek = Stream.Seek;
            if (!Stream.ReadInteger(Stream.ReadType(), &Checksum))
                return Optional::None;

            if (Checksum != Util::Sha64d(std::string_view(Stream.Data.data(), Seek)))
                return Optional::None;

            GmpSignature Result;
            Result.T = T;
            mpz_init(Result.P);
            mpz_init(Result.L);
            mpz_init(Result.Y);
            mpz_init(Result.N);
            mpz_import(Result.P, P.size(), 1, 1, 1, 0, P.data());
            mpz_import(Result.L, L.size(), 1, 1, 1, 0, L.data());
            mpz_import(Result.Y, Y.size(), 1, 1, 1, 0, Y.data());
            mpz_import(Result.N, N.size(), 1, 1, 1, 0, N.data());
            return Result;
        }
        static void HashMessage(const std::string_view& Value, mpz_t V)
        {
            uint8_t Hash[64];
            Algorithm::Hashing::Hash512((uint8_t*)Value.data(), Value.size(), Hash);
            mpz_init(V);
            mpz_import(V, sizeof(Hash), -1, 1, 0, 0, Hash);
        }
        static void ClearSignature(GmpSignature& Sig)
        {
            mpz_clear(Sig.P);
            mpz_clear(Sig.L);
            mpz_clear(Sig.Y);
            mpz_clear(Sig.N);
        }
#endif
        uint256_t Util::Sha256ci(const uint256_t& A, const uint256_t& B)
        {
            uint8_t CombineBuffer[sizeof(uint256_t) * 2];
            Algorithm::Encoding::DecodeUint256(A, CombineBuffer + sizeof(uint256_t) * 0);
            Algorithm::Encoding::DecodeUint256(B, CombineBuffer + sizeof(uint256_t) * 1);
            return Algorithm::Hashing::Hash256i(CombineBuffer, sizeof(CombineBuffer));
        }
        uint64_t Util::Sha64d(const uint8_t* Buffer, size_t Size)
        {
            uint64_t Checksum = 0;
            if (!Size)
                return uint64_t(0);

            String Hash = Algorithm::Hashing::Hash256(Buffer, Size);
            if (Hash.size() < sizeof(Checksum))
                return uint64_t(0);

            memcpy(&Checksum, Hash.data(), sizeof(Checksum));
            return Checksum;
        }
        uint64_t Util::Sha64d(const std::string_view& Buffer)
        {
            return Sha64d((uint8_t*)Buffer.data(), Buffer.size());
        }

        uint256_t MerkleTree::Path::CalculateRoot(uint256_t Hash) const
        {
            size_t Offset = Index;
            for (size_t i = 0; i < Nodes.size(); i++)
            {
                Hash = (Offset & 1 ? Hasher(Nodes[i], Hash) : Hasher(Hash, Nodes[i]));
                Offset >>= 1;
            }
            return Hash;
        }
        Vector<uint256_t>& MerkleTree::Path::GetBranch()
        {
            return Nodes;
        }
        const Vector<uint256_t>& MerkleTree::Path::GetBranch() const
        {
            return Nodes;
        }
        size_t MerkleTree::Path::GetIndex() const
        {
            return Index;
        }
        bool MerkleTree::Path::Empty()
        {
            return Nodes.empty();
        }

        MerkleTree::MerkleTree()
        {
        }
        MerkleTree::MerkleTree(const uint256_t& PrevMerkleRoot)
        {
            if (PrevMerkleRoot > 0)
                Push(PrevMerkleRoot);
        }
        MerkleTree& MerkleTree::Shift(const uint256_t& Hash)
        {
            Nodes.insert(Nodes.begin(), Hash);
            ++Hashes;
            return *this;
        }
        MerkleTree& MerkleTree::Push(const uint256_t& Hash)
        {
            Nodes.push_back(Hash);
            ++Hashes;
            return *this;
        }
        MerkleTree& MerkleTree::Reset()
        {
            Nodes.clear();
            Hashes = 0;
            return *this;
        }
        MerkleTree& MerkleTree::Calculate()
        {
            VI_ASSERT(Hasher != nullptr, "hash function should be set");
            if (IsCalculated())
                return *this;

            std::sort(Nodes.begin(), Nodes.end());
            for (size_t Size = Hashes, Node = 0; Size > 1; Size = (Size + 1) / 2)
            {
                for (size_t Offset = 0; Offset < Size; Offset += 2)
                    Nodes.push_back(Hasher(Nodes[Node + Offset], Nodes[Node + std::min(Offset + 1, Size - 1)]));
                Node += Size;
            }
            return *this;
        }
        MerkleTree::Path MerkleTree::CalculatePath(const uint256_t& Hash)
        {
            Path Branch;
            Branch.Hasher = Hasher;
            Calculate();

            auto Begin = Nodes.begin(), End = Nodes.begin() + Hashes;
            auto It = std::lower_bound(Nodes.begin(), Nodes.begin() + Hashes, Hash);
            if (It == End)
                return Branch;

            size_t Index = It - Begin;
            Branch.Index = Index;

            for (size_t Size = Hashes, Node = 0; Size > 1; Size = (Size + 1) / 2)
            {
                Branch.Nodes.push_back(Nodes[Node + std::min(Index ^ 1, Size - 1)]);
                Index >>= 1;
                Node += Size;
            }

            return Branch;
        }
        uint256_t MerkleTree::CalculateRoot()
        {
            Calculate();
            return Nodes.empty() ? uint256_t(0) : Nodes.back();
        }
        const Vector<uint256_t>& MerkleTree::GetTree()
        {
            if (!IsCalculated())
                Calculate();

            return Nodes;
        }
        const Vector<uint256_t>& MerkleTree::GetTree() const
        {
            return Nodes;
        }
        size_t MerkleTree::GetComplexity() const
        {
            return Hashes;
        }
        bool MerkleTree::IsCalculated() const
        {
            return !Hashes || Hashes < Nodes.size();
        }

        uint128_t WesolowskiVDF::Parameters::Difficulty() const
        {
            return uint128_t(Length) * uint128_t(Bits) + uint128_t(Pow);
        }

        uint256_t WesolowskiVDF::Distribution::Derive()
        {
            return Derive(Nonce++);
        }
        uint256_t WesolowskiVDF::Distribution::Derive(const uint256_t& Step) const
        {
            char Data[sizeof(uint256_t) * 2] = { 0 };
            Algorithm::Encoding::DecodeUint256(Step, (uint8_t*)((char*)Data + sizeof(uint256_t) * 0));
            Algorithm::Encoding::DecodeUint256(Value, (uint8_t*)((char*)Data + sizeof(uint256_t) * 1));
            return Algorithm::Hashing::Hash256i(std::string_view(Data, sizeof(Data)));
        }

        WesolowskiVDF::Distribution WesolowskiVDF::Random(const Parameters& Alg, const Format::Stream& Seed)
        {
            Distribution Result;
            Result.Signature = Provability::WesolowskiVDF::Evaluate(Alg, Seed.Data);
            Result.Value = Algorithm::Hashing::Hash256i(*Crypto::HashRaw(Digests::SHA512(), Result.Signature));
            return Result;
        }
        WesolowskiVDF::Parameters WesolowskiVDF::Calibrate(uint64_t Confidence)
        {
            uint64_t TargetNonce = Confidence;
            uint64_t TargetTime = Protocol::Now().Policy.ConsensusProofTime;
            auto Alg = DefaultAlg;
            while (true)
            {
            Retry:
                uint64_t StartTime = Protocol::Now().Time.Now();
                auto Signature = Evaluate(Alg, *Crypto::RandomBytes(Math32u::Random(256, 1024)));
                if (Signature.empty())
                    break;

                uint64_t EndTime = Protocol::Now().Time.Now();
                uint64_t DeltaTime = EndTime - StartTime;
                double DeltaTarget =(double)DeltaTime - (double)TargetTime;
                if (std::abs(DeltaTarget) / TargetTime < 0.05)
                {
                    if (!TargetNonce--)
                        break;
                    goto Retry;
                }

                Alg = Adjust(Alg, 0, DeltaTime, AdjustmentInterval());
                TargetNonce = Confidence;
            }
            return Alg;
        }
        WesolowskiVDF::Parameters WesolowskiVDF::Adjust(const Parameters& PrevAlg, uint64_t PrevPriority, uint64_t PrevTime, uint64_t TargetIndex)
        {
            if (TargetIndex <= 1)
                return DefaultAlg;

            if (AdjustmentIndex(TargetIndex) != TargetIndex)
            {
            LeaveAsIs:
                return (PrevAlg.Difficulty() < DefaultAlg.Difficulty() ? DefaultAlg : PrevAlg);
            }
            else if (PrevPriority != 0)
                return PrevAlg;

            auto& Policy = Protocol::Now().Policy;
            PrevTime = std::max(Policy.ConsensusProofTime / 4, std::min(Policy.ConsensusProofTime * 4, PrevTime));

            int64_t TimeDelta = (int64_t)Policy.ConsensusProofTime - (int64_t)PrevTime;
            if (std::abs((double)TimeDelta) / (double)Policy.ConsensusProofTime < 0.05)
                goto LeaveAsIs;

            Parameters NewAlg = PrevAlg;
            Decimal Adjustment = Decimal(TimeDelta).Truncate(Protocol::Now().Message.Precision) / PrevTime;
            if (Adjustment > 1.0 + Policy.MaxConsensusDifficultyIncrease)
                Adjustment = 1.0 + Policy.MaxConsensusDifficultyIncrease;
            else if (Adjustment < Policy.MaxConsensusDifficultyDecrease)
                Adjustment = Policy.MaxConsensusDifficultyDecrease;

            NewAlg.Pow = abs((int64_t)NewAlg.Pow + (Decimal(NewAlg.Pow) * Adjustment).ToInt64());
            if (NewAlg.Pow < DefaultAlg.Pow)
                NewAlg.Pow = DefaultAlg.Pow;

            return (NewAlg.Difficulty() < DefaultAlg.Difficulty() ? DefaultAlg : NewAlg);
        }
        String WesolowskiVDF::Evaluate(const Parameters& Alg, const std::string_view& Message)
        {
#ifdef TAN_GMP
            mpz_t V;
            HashMessage(Message, V);

            GmpSignature Signature;
            mpz_init(Signature.P);
            mpz_init(Signature.L);
            mpz_init(Signature.Y);
            mpz_init(Signature.N);

            gmp_randstate_t R;
            gmp_randinit_mt(R);
            gmp_randseed(R, V);

            mpz_t P;
            mpz_init(P);
            mpz_urandomb(P, R, Alg.Length / 2);
            mpz_nextprime(P, P);

            mpz_t Q;
            mpz_init(Q);
            mpz_urandomb(Q, R, Alg.Length / 2);
            mpz_nextprime(Q, Q);
            mpz_init(Signature.N);
            mpz_mul(Signature.N, P, Q);
            mpz_clear(P);
            mpz_clear(Q);

            mpz_t E, C;
            mpz_init(E);
            mpz_ui_pow_ui(E, 2, Alg.Pow);
            mpz_init(Signature.Y);
            mpz_init(C);
            mpz_urandomb(C, R, 2 * Alg.Bits);
            mpz_nextprime(Signature.L, C);
            mpz_init(Q);
            mpz_powm(Signature.Y, V, E, Signature.N);
            mpz_fdiv_q(Q, E, Signature.L);
            mpz_powm(Signature.P, V, Q, Signature.N);
            mpz_clear(Q);
            mpz_clear(E);
            mpz_clear(C);
            mpz_clear(V);
            gmp_randclear(R);

            Signature.T = Protocol::Now().Time.Now();
            String Result = SerializeSignature(Signature);
            ClearSignature(Signature);
            return Result;
#else
            return String();
#endif
        }
        bool WesolowskiVDF::Verify(const Parameters& Alg, const std::string_view& Message, const String& Sig)
        {
#ifdef TAN_GMP
            auto Signature = DeserializeSignature(Sig);
            if (!Signature)
                return false;

            mpz_t V;
            HashMessage(Message, V);

            mpz_t P;
            mpz_init(P);
            mpz_sub_ui(P, Signature->L, 1);

            mpz_t T;
            mpz_init(T);
            mpz_set_ui(T, Alg.Pow);
            mpz_mod(T, T, P);
            mpz_clear(P);

            mpz_t D;
            mpz_init(D);
            mpz_set_ui(D, 2);

            mpz_t R;
            mpz_init(R);
            mpz_powm(R, D, T, Signature->L);
            mpz_clear(T);
            mpz_clear(D);

            mpz_t Y, W;
            mpz_init(Y);
            mpz_init(W);
            mpz_powm(Y, Signature->P, Signature->L, Signature->N);
            mpz_powm(W, V, R, Signature->N);
            mpz_mul(Y, Y, W);
            mpz_mod(Y, Y, Signature->N);
            mpz_clear(R);
            mpz_clear(W);
            mpz_clear(V);

            bool Verified = mpz_cmp(Y, Signature->Y) == 0;
            ClearSignature(*Signature);
            mpz_clear(Y);
            return Verified;
#else
            return false;
#endif
        }
        int8_t WesolowskiVDF::Compare(const String& Sig1, const String& Sig2)
        {
#ifdef TAN_GMP
            auto Signature1 = DeserializeSignature(Sig1);
            auto Signature2 = DeserializeSignature(Sig2);
            if (!Signature1 || !Signature2)
                return Signature1 ? 1 : -1;

            int CompareY = mpz_cmp(Signature1->Y, Signature2->Y);
            if (CompareY != 0)
                return (int8_t)CompareY;

            int CompareP = mpz_cmp(Signature1->P, Signature2->P);
            if (CompareP != 0)
                return (int8_t)CompareP;

            int CompareN = mpz_cmp(Signature1->N, Signature2->N);
            if (CompareN != 0)
                return (int8_t)CompareN;

            int CompareL = mpz_cmp(Signature1->L, Signature2->L);
            if (CompareL != 0)
                return (int8_t)CompareL;

            if (Signature1->T < Signature2->T)
                return 1;
            else if (Signature1->T > Signature2->T)
                return -1;

            return 0;
#else
            return -2;
#endif
        }
        uint64_t WesolowskiVDF::Locktime(const String& Sig)
        {
#ifdef TAN_GMP
            auto Signature = DeserializeSignature(Sig);
            if (!Signature)
                return 0;

            ClearSignature(*Signature);
            return Signature->T;
#endif
        }
        uint64_t WesolowskiVDF::AdjustmentInterval()
        {
            auto& Policy = Protocol::Now().Policy;
            return Policy.ConsensusAdjustmentTime / Policy.ConsensusProofTime;
        }
        uint64_t WesolowskiVDF::AdjustmentIndex(uint64_t Index)
        {
            return Index - Index % AdjustmentInterval();
        }
        void WesolowskiVDF::SetDefault(const Parameters& Alg)
        {
            DefaultAlg = Alg;
        }
        const WesolowskiVDF::Parameters& WesolowskiVDF::GetDefault()
        {
            return DefaultAlg;
        }
        WesolowskiVDF::Parameters WesolowskiVDF::DefaultAlg;
    }
}