#ifndef TAN_LAYER_CONTROL_H
#define TAN_LAYER_CONTROL_H
#include "../kernel/chain.h"

namespace Tangent
{
	struct SystemEndpoint
	{
		Location Scheme;
		SocketAddress Address;
		bool Secure;

		SystemEndpoint(const std::string_view& URI);
		bool IsValid() const;
		static String ToURI(const SocketAddress& Address, const std::string_view& Protocol = "tcp");
	};

	struct SystemControl
	{
		UnorderedMap<String, TaskId>* Timers;
		std::atomic<size_t> Tasks;
		std::atomic<bool> Active;
		std::recursive_mutex Sync;
		std::string_view ServiceName;

		SystemControl(const std::string_view& Label) noexcept;
		Promise<void> Shutdown() noexcept;
		bool LockTimeout(const std::string_view& Name);
		bool UnlockTimeout(const std::string_view& Name);
		bool IntervalIfNone(const std::string_view& Name, uint64_t Ms, TaskCallback&& Callback) noexcept;
		bool TimeoutIfNone(const std::string_view& Name, uint64_t Ms, TaskCallback&& Callback) noexcept;
		bool UpsertTimeout(const std::string_view& Name, uint64_t Ms, TaskCallback&& Callback) noexcept;
		bool ClearTimeout(const std::string_view& Name, bool ClearScheduled = false) noexcept;
		bool ActivateAndEnqueue() noexcept;
		bool Deactivate() noexcept;
		bool EnqueueIfNone() noexcept;
		bool Enqueue() noexcept;
		bool Dequeue() noexcept;
		bool IsActive() noexcept;
		bool IsBusy() noexcept;
	};

	struct ServiceControl
	{
	public:
		struct ServiceNode
		{
			std::function<void()> Startup;
			std::function<void()> Shutdown;
		};

	private:
		static ServiceControl* Instance;

	private:
		Vector<ServiceNode> Services;
		std::atomic<int> ExitCode;

	public:
		ServiceControl() noexcept;
		void Bind(ServiceNode&& Entrypoint) noexcept;
		void Shutdown(int Signal) noexcept;
		void Abort(int Signal) noexcept;
		int Launch() noexcept;

	private:
		template <Signal Type>
		static void BindNormalTermination()
		{
			OS::Process::BindSignal(Type, [](int Signal)
			{
				OS::Process::RebindSignal(Type);
				if (Instance != nullptr)
					Instance->Shutdown(Signal);
			});
		}
		template <Signal Type>
		static void BindFatalTermination()
		{
			OS::Process::BindSignal(Type, [](int Signal)
			{
				OS::Process::RebindSignal(Type);
				if (Instance != nullptr)
					Instance->Abort(Signal);
			});
		}
	};
}
#endif