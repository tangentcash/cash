#ifndef TAN_KERNEL_SVM_H
#define TAN_KERNEL_SVM_H
#include "block.h"

namespace tangent
{
	namespace ledger
	{
		using namespace vitex::scripting;

		class svm_compiler;

		struct svm_program;

		enum class svm_call
		{
			system_call,
			mutable_call,
			immutable_call
		};

		class svm_marshalling
		{
		public:
			static expects_lr<void> store(format::wo_stream* stream, const void* value, int value_type_id);
			static expects_lr<void> store(schema* stream, const void* value, int value_type_id);
			static expects_lr<void> load(format::ro_stream& stream, void* value, int value_type_id);
			static expects_lr<void> load(schema* stream, void* value, int value_type_id);
		};

		class svm_container : public singleton<svm_container>
		{
		private:
			unordered_set<std::string_view> illegal_instructions;
			unordered_map<string, asIScriptModule*> modules;
			single_queue<uptr<compiler>> compilers;
			uptr<virtual_machine> vm;
			std::mutex mutex;
			void* strings;

		public:
			std::mutex exclusive;

		public:
			svm_container() noexcept;
			virtual ~svm_container() noexcept override;
			svm_compiler allocate();
			void deallocate(uptr<compiler>&& compiler);
			expects_lr<void> compile(compiler* compiler, const std::string_view& program_hashcode, const std::string_view& program_name, const std::string_view& unpacked_program_code);
			bool precompile(compiler* compiler, const std::string_view& program_hashcode);
			string hashcode(const std::string_view& unpacked_program_code);
			expects_lr<string> pack(const std::string_view& unpacked_program_code);
			expects_lr<string> unpack(const std::string_view& packed_program_code);
			virtual_machine* get_vm();

		private:
			expects_lr<void> validate_bytecode(const function& compiled_function);
			static const void* to_string_constant(void* context, const char* buffer, size_t buffer_size);
			static int from_string_constant(void* context, const void* object, char* buffer, size_t* buffer_size);
			static int free_string_constant(void* context, const void* object);
		};

		class svm_compiler
		{
		private:
			compiler* address;

		public:
			svm_compiler() noexcept : address(nullptr)
			{
			}
			svm_compiler(compiler* new_address) noexcept : address(new_address)
			{
			}
			svm_compiler(const svm_compiler&) noexcept = delete;
			svm_compiler(svm_compiler&& other) noexcept : address(other.address)
			{
				other.address = nullptr;
			}
			~svm_compiler()
			{
				destroy();
			}
			svm_compiler& operator= (const svm_compiler&) noexcept = delete;
			svm_compiler& operator= (svm_compiler&& other) noexcept
			{
				if (this == &other)
					return *this;

				destroy();
				address = other.address;
				other.address = nullptr;
				return *this;
			}
			explicit operator bool() const
			{
				return address != nullptr;
			}
			inline compiler* operator-> ()
			{
				VI_ASSERT(address != nullptr, "unique null pointer access");
				return address;
			}
			inline compiler* operator-> () const
			{
				VI_ASSERT(address != nullptr, "unique null pointer access");
				return address;
			}
			inline compiler* operator* ()
			{
				return address;
			}
			inline compiler* operator* () const
			{
				return address;
			}
			inline compiler** out()
			{
				VI_ASSERT(!address, "pointer should be null when performing output update");
				return &address;
			}
			inline compiler* const* in() const
			{
				return &address;
			}
			inline compiler* expect(const std::string_view& message)
			{
				VI_PANIC(address != nullptr, "%.*s CAUSING panic", (int)message.size(), message.data());
				return address;
			}
			inline compiler* expect(const std::string_view& message) const
			{
				VI_PANIC(address != nullptr, "%.*s CAUSING panic", (int)message.size(), message.data());
				return address;
			}
			inline compiler* reset()
			{
				compiler* result = address;
				address = nullptr;
				return result;
			}
			inline void destroy()
			{
				if (svm_container::has_instance())
					svm_container::get()->deallocate(reset());
				else
					memory::release(address);
			}
		};

		struct svm_stackframe
		{
			function call = nullptr;
			size_t byte_code_size = 0;
			uint32_t* byte_code = nullptr;
			uint32_t pointer = 0;

			static size_t gas_cost_of(const byte_code_label& opcode);
		};

		struct svm_program
		{
			struct
			{
				option<algorithm::wesolowski::distribution> distribution = optional::none;
				unordered_map<string, unordered_map<size_t, uptr<states::account_multiform>>> columns;
				unordered_map<string, unordered_map<size_t, uptr<states::account_multiform>>> rows;
			} cache;
			ledger::transaction_context* context;

			svm_program(ledger::transaction_context* new_context);
			virtual expects_lr<void> construct(compiler* compiler, const format::variables& args);
			virtual expects_lr<void> mutable_call(compiler* compiler, const std::string_view& function_decl, const format::variables& args);
			virtual expects_lr<void> immutable_call(compiler* compiler, const std::string_view& function_decl, const format::variables& args);
			virtual expects_lr<void> execute(svm_call mutability, const function& entrypoint, const format::variables& args, std::function<expects_lr<void>(void*, int)>&& return_callback);
			virtual expects_lr<void> subexecute(const algorithm::pubkeyhash_t& target, svm_call mutability, const std::string_view& function_decl, format::variables&& function_args, void* output_value, int output_type_id) const;
			virtual expects_lr<vector<std::function<void(immediate_context*)>>> dispatch_arguments(svm_call* mutability, const function& entrypoint, const format::variables& args) const;
			virtual void dispatch_exception(immediate_context* coroutine);
			virtual void dispatch_coroutine(immediate_context* coroutine, vector<svm_stackframe>& frames);
			virtual bool dispatch_instruction(virtual_machine* vm, immediate_context* coroutine, uint32_t* program_data, size_t program_counter, byte_code_label& opcode);
			virtual bool emit_event(const void* object_value, int object_type_id);
            virtual svm_call mutability_of(const function& entrypoint) const;
			virtual algorithm::pubkeyhash_t callable() const;
			virtual decimal payable() const;
			virtual string function_declaration() const;
			virtual const format::variables* function_arguments() const;
			static svm_program* fetch_mutable(immediate_context* coroutine = immediate_context::get());
			static const svm_program* fetch_immutable(immediate_context* coroutine = immediate_context::get());
			static svm_program* fetch_mutable_or_throw(immediate_context* coroutine = immediate_context::get());
			static const svm_program* fetch_immutable_or_throw(immediate_context* coroutine = immediate_context::get());
		};
	}
}
#endif
