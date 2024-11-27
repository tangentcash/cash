#ifndef TAN_KERNEL_SCRIPT_H
#define TAN_KERNEL_SCRIPT_H
#include "block.h"

using namespace Vitex::Scripting;

namespace Tangent
{
	namespace Ledger
	{
		class ScriptMarshalling
		{
		public:
			static ExpectsLR<void> Store(Format::Stream* Stream, void* Value, int ValueTypeId);
			static ExpectsLR<void> Store(Schema* Stream, void* Value, int ValueTypeId);
			static ExpectsLR<void> Load(Format::Stream& Stream, void* Value, int ValueTypeId);
			static ExpectsLR<void> Load(Schema* Stream, void* Value, int ValueTypeId);
		};

		class ScriptHost : public Singleton<ScriptHost>
		{
		private:
			UnorderedMap<String, asIScriptModule*> Modules;
			SingleQueue<UPtr<Compiler>> Compilers;
			UPtr<VirtualMachine> VM;
			std::mutex Mutex;

		public:
			ScriptHost() noexcept;
			virtual ~ScriptHost() noexcept override;
			UPtr<Compiler> Allocate();
			void Deallocate(UPtr<Compiler>&& Compiler);
			ExpectsLR<void> Compile(Compiler* Compiler, const std::string_view& ProgramHashcode, const std::string_view& UnpackedProgramCode);
			bool Precompile(Compiler* Compiler, const std::string_view& ProgramHashcode);
			String Hashcode(const std::string_view& UnpackedProgramCode);
			ExpectsLR<String> Pack(const std::string_view& UnpackedProgramCode);
			ExpectsLR<String> Unpack(const std::string_view& PackedProgramCode);
			VirtualMachine* GetVM();
		};

		struct ScriptFrame
		{
			Function Call = nullptr;
			size_t ByteCodeSize = 0;
			uint32_t* ByteCode = nullptr;
			uint32_t Pointer = 0;
		};

		struct ScriptAddress
		{
			Algorithm::Pubkeyhash Hash = { 0 };

			ScriptAddress();
			ScriptAddress(const Algorithm::Pubkeyhash Owner);
			ScriptAddress(const std::string_view& Address);
			ScriptAddress(const uint256_t& Numeric);
			String ToString() const;
			uint256_t ToUint256() const;
			bool IsNull() const;
			static bool Equals(const ScriptAddress& A, const ScriptAddress& B);
		};

		struct ScriptProgram
		{
			Option<Provability::WesolowskiVDF::Distribution> Distribution;
			Ledger::TransactionContext* Context;

			ScriptProgram(Ledger::TransactionContext* NewContext);
			virtual ExpectsLR<void> Initialize(Compiler* Compiler, const Format::Variables& Args);
			virtual ExpectsLR<void> MutableCall(Compiler* Compiler, const std::string_view& Function, const Format::Variables& Args);
			virtual ExpectsLR<void> ImmutableCall(Compiler* Compiler, const std::string_view& Function, const Format::Variables& Args);
			virtual bool DispatchInstruction(VirtualMachine* VM, ImmediateContext* Coroutine, uint32_t* ProgramData, size_t ProgramCounter, ByteCodeLabel& Opcode);
			virtual bool CallMutableFunction(const ScriptAddress& Target, const std::string_view& Function, void* InputValue, int InputTypeId, void* OutputValue, int OutputTypeId);
			virtual bool CallImmutableFunction(const ScriptAddress& Target, const std::string_view& Function, void* InputValue, int InputTypeId, void* OutputValue, int OutputTypeId) const;
			virtual bool StoreByAddress(const ScriptAddress& Location, const void* ObjectValue, int ObjectTypeId);
			virtual bool StoreByLocation(const std::string_view& Location, const void* ObjectValue, int ObjectTypeId);
			virtual bool LoadByAddress(const ScriptAddress& Location, void* ObjectValue, int ObjectTypeId) const;
			virtual bool LoadByLocation(const std::string_view& Location, void* ObjectValue, int ObjectTypeId) const;
			virtual bool LoadFromByAddress(const ScriptAddress& Target, const ScriptAddress& Location, void* ObjectValue, int ObjectTypeId) const;
			virtual bool LoadFromByLocation(const ScriptAddress& Target, const std::string_view& Location, void* ObjectValue, int ObjectTypeId) const;
			virtual bool EmitByAddress(const ScriptAddress& Location, const void* ObjectValue, int ObjectTypeId);
			virtual bool EmitByLocation(const std::string_view& Location, const void* ObjectValue, int ObjectTypeId);
			virtual bool Transfer(const ScriptAddress& To, const uint256_t& Asset, const Decimal& Value);
			virtual uint64_t AccountSequenceOf(const ScriptAddress& Target) const;
			virtual uint256_t AccountWorkOf(const ScriptAddress& Target) const;
			virtual String AccountProgramOf(const ScriptAddress& Target) const;
			virtual Decimal AccountIncomingRewardOf(const ScriptAddress& Target, const Algorithm::AssetId& Asset, const Decimal& Value) const;
			virtual Decimal AccountOutgoingRewardOf(const ScriptAddress& Target, const Algorithm::AssetId& Asset, const Decimal& Value) const;
			virtual uint64_t AccountDerivationOf(const ScriptAddress& Target, const Algorithm::AssetId& Asset) const;
			virtual Decimal AccountBalanceOf(const ScriptAddress& Target, const Algorithm::AssetId& Asset) const;
			virtual Decimal AccountContributionOf(const ScriptAddress& Target, const Algorithm::AssetId& Asset) const;
			virtual bool HasWitnessProgramOf(const std::string_view& Hashcode) const;
			virtual uint256_t WitnessEventOf(const uint256_t& TransactionHash) const;
			virtual ScriptAddress WitnessAddressOf(const Algorithm::AssetId& Asset, const std::string_view& Address, uint64_t AddressIndex, size_t Offset) const;
			virtual bool HasWitnessTransactionOf(const Algorithm::AssetId& Asset, const std::string_view& TransactionId) const;
			virtual uint256_t Random();
			virtual ScriptAddress From() const;
			virtual ScriptAddress To() const;
			virtual String Blockchain() const;
			virtual String Token() const;
			virtual String Contract() const;
			virtual Decimal GasPrice() const;
			virtual uint256_t GasLeft() const;
			virtual uint256_t GasUse() const;
			virtual uint256_t GasLimit() const;
			virtual uint256_t Asset() const;
			virtual uint256_t ParentBlockHash() const;
			virtual uint256_t BlockGasLeft() const;
			virtual uint256_t BlockGasUse() const;
			virtual uint256_t BlockGasLimit() const;
			virtual uint128_t BlockDifficulty() const;
			virtual uint64_t BlockTime() const;
			virtual uint64_t BlockPriority() const;
			virtual uint64_t BlockNumber() const;

		protected:
			virtual ExpectsLR<void> Execute(Compiler* Compiler, const std::string_view& Function, const Format::Variables& Args, int8_t Mutable, std::function<ExpectsLR<void>(void*, int)>&& ReturnCallback);
			virtual ExpectsLR<void> Subexecute(const ScriptAddress& Target, const std::string_view& Function, void* InputValue, int InputTypeId, void* OutputValue, int OutputTypeId, int8_t Mutable) const;
			virtual ExpectsLR<Vector<std::function<void(ImmediateContext*)>>> LoadArguments(const Function& Entrypoint, const Format::Variables& Args, int8_t Mutable) const;
			virtual void LoadCoroutine(ImmediateContext* Coroutine, Vector<ScriptFrame>& Frames);
		};

		struct ScriptProgramTrace : ScriptProgram
		{
			UPtr<Schema> Returning;
			Vector<String> Instructions;
			EvaluationContext Environment;
			Ledger::Block Block;
			bool Debugging;

			ScriptProgramTrace(Ledger::Transaction* Transaction, const Algorithm::Pubkeyhash From, bool Tracing);
			ExpectsLR<void> TraceCall(const std::string_view& Function, const Format::Variables& Args, int8_t Mutable);
			bool DispatchInstruction(VirtualMachine* VM, ImmediateContext* Coroutine, uint32_t* ProgramData, size_t ProgramCounter, ByteCodeLabel& Opcode) override;
			UPtr<Schema> AsSchema() const;
		};
	}
}
#endif