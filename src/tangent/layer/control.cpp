#include "control.h"
#include <iostream>
#define LOCKED_TASK_ID std::numeric_limits<uint64_t>::max()

namespace Tangent
{
	SystemControl::SystemControl(const std::string_view& Label) noexcept : Timers(nullptr), Tasks(0), Active(false), ServiceName(Label.empty() ? "unknown" : Label)
	{
	}
	Promise<void> SystemControl::Shutdown() noexcept
	{
		VI_PANIC(!Active, "controller is still active");
		if (!IsBusy())
		{
			VI_DEBUG("[sysctl] OK shutdown %.*s service", (int)ServiceName.size(), ServiceName.data());
			CoreturnVoid;
		}

		Promise<void> Timeout;
		std::thread([this, Timeout]() mutable
		{
			auto Time = time(nullptr);
			while (IsBusy())
			{
				std::this_thread::sleep_for(std::chrono::milliseconds(500));
				if (time(nullptr) - Time > 2)
					VI_DEBUG("[sysctl] waiting %i tasks on %.*s service to finish (longer than expected)", (int)Tasks.load(), (int)ServiceName.size(), ServiceName.data());
			}
			Timeout.Set();
		}).detach();

		uint64_t TimeStart = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
		VI_DEBUG("[sysctl] waiting on %.*s service to finish (queue = %i tasks)", (int)ServiceName.size(), ServiceName.data(), (int)Tasks.load());
		Coawait(std::move(Timeout));

		uint64_t TimeEnd = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
		VI_DEBUG("[sysctl] OK shutdown %.*s service (wait = %" PRIu64 " ms)", (int)ServiceName.size(), ServiceName.data(), TimeEnd - TimeStart);
		CoreturnVoid;
	}
	bool SystemControl::LockTimeout(const std::string_view& Name)
	{
		UMutex<std::recursive_mutex> Unique(Sync);
		if (!Active)
		{
			VI_DEBUG("[sysctl] cancel %.*s lock on %.*s service: shutdown", (int)Name.size(), Name.data(), (int)ServiceName.size(), ServiceName.data());
			return false;
		}

		VI_ASSERT(Timers != nullptr, "timers should be initialized");
		if (Timers->find(KeyLookupCast(Name)) == Timers->end())
			VI_DEBUG("[sysctl] OK spawn %.*s locked task on %.*s service (mode = lock-timeout)", (int)Name.size(), Name.data(), (int)ServiceName.size(), ServiceName.data());

		auto& Timer = (*Timers)[String(Name)];
		if (Timer != INVALID_TASK_ID)
		{
			VI_DEBUG("[sysctl] cancel %.*s lock on %.*s service: in use", (int)Name.size(), Name.data(), (int)ServiceName.size(), ServiceName.data());
			return false;
		}

		Timer = LOCKED_TASK_ID;
		return true;
	}
	bool SystemControl::UnlockTimeout(const std::string_view& Name)
	{
		UMutex<std::recursive_mutex> Unique(Sync);
		if (!Active)
		{
			VI_DEBUG("[sysctl] cancel %.*s unlock on %.*s service: shutdown", (int)Name.size(), Name.data(), (int)ServiceName.size(), ServiceName.data());
			return false;
		}

		VI_ASSERT(Timers != nullptr, "timers should be initialized");
		if (Timers->find(KeyLookupCast(Name)) == Timers->end())
		{
			VI_DEBUG("[sysctl] cancel %.*s unlock on %.*s service: not locked", (int)Name.size(), Name.data(), (int)ServiceName.size(), ServiceName.data());
			return false;
		}

		auto& Timer = (*Timers)[String(Name)];
		if (Timer == LOCKED_TASK_ID)
			Timer = INVALID_TASK_ID;
		return true;
	}
	bool SystemControl::IntervalIfNone(const std::string_view& Name, uint64_t Ms, TaskCallback&& Callback) noexcept
	{
		UMutex<std::recursive_mutex> Unique(Sync);
		if (!Active)
		{
			VI_DEBUG("[sysctl] cancel %.*s interval on %.*s service: shutdown", (int)Name.size(), Name.data(), (int)ServiceName.size(), ServiceName.data());
			return false;
		}

		VI_ASSERT(Timers != nullptr, "timers should be initialized");
		if (Timers->find(KeyLookupCast(Name)) == Timers->end())
			VI_DEBUG("[sysctl] OK spawn %.*s task on %.*s service (mode = interval, delay = %" PRIu64 " ms)", (int)Name.size(), Name.data(), (int)ServiceName.size(), ServiceName.data(), Ms);

		auto& Timer = (*Timers)[String(Name)];
		if (Timer != INVALID_TASK_ID || Timer == LOCKED_TASK_ID)
			return false;

		Timer = Schedule::Get()->SetInterval(Ms, std::move(Callback));
		if (Timer != INVALID_TASK_ID)
			return true;

		VI_DEBUG("[sysctl] cancel %.*s interval on %.*s service: inactive", (int)Name.size(), Name.data(), (int)ServiceName.size(), ServiceName.data());
		return false;
	}
	bool SystemControl::TimeoutIfNone(const std::string_view& Name, uint64_t Ms, TaskCallback&& Callback) noexcept
	{
		UMutex<std::recursive_mutex> Unique(Sync);
		if (!Active)
		{
			VI_DEBUG("[sysctl] cancel %.*s timeout on %.*s service: shutdown", (int)Name.size(), Name.data(), (int)ServiceName.size(), ServiceName.data());
			return false;
		}

		VI_ASSERT(Timers != nullptr, "timers should be initialized");
		if (Timers->find(KeyLookupCast(Name)) == Timers->end())
			VI_DEBUG("[sysctl] OK spawn %.*s task on %.*s service (mode = timeout, delay = %" PRIu64 " ms)", (int)Name.size(), Name.data(), (int)ServiceName.size(), ServiceName.data(), Ms);

		auto& Timer = (*Timers)[String(Name)];
		if (Timer != INVALID_TASK_ID || Timer == LOCKED_TASK_ID)
			return false;

		Timer = Schedule::Get()->SetTimeout(Ms, std::move(Callback));
		if (Timer != INVALID_TASK_ID)
			return true;

		VI_DEBUG("[sysctl] cancel %.*s timeout on %.*s service: inactive", (int)Name.size(), Name.data(), (int)ServiceName.size(), ServiceName.data());
		return false;
	}
	bool SystemControl::UpsertTimeout(const std::string_view& Name, uint64_t Ms, TaskCallback&& Callback) noexcept
	{
		UMutex<std::recursive_mutex> Unique(Sync);
		if (!Active)
		{
			VI_DEBUG("[sysctl] cancel %.*s timeout on %.*s service: shutdown", (int)Name.size(), Name.data(), (int)ServiceName.size(), ServiceName.data());
			return false;
		}

		VI_ASSERT(Timers != nullptr, "timers should be initialized");
		if (Timers->find(KeyLookupCast(Name)) == Timers->end())
			VI_DEBUG("[sysctl] OK spawn %.*s task on %.*s service (mode = upsert-timeout, delay = %" PRIu64 " ms)", (int)Name.size(), Name.data(), (int)ServiceName.size(), ServiceName.data(), Ms);

		auto& Timer = (*Timers)[String(Name)];
		if (Timer == LOCKED_TASK_ID)
			return false;

		Timer = Schedule::Get()->SetTimeout(Ms, std::move(Callback));
		if (Timer != INVALID_TASK_ID)
			return true;

		VI_DEBUG("[sysctl] cancel %.*s timeout on %.*s service: inactive", (int)Name.size(), Name.data(), (int)ServiceName.size(), ServiceName.data());
		return false;
	}
	bool SystemControl::ClearTimeout(const std::string_view& Name, bool ClearScheduled) noexcept
	{
		UMutex<std::recursive_mutex> Unique(Sync);
		if (!Active)
			return false;

		VI_ASSERT(Timers != nullptr, "timers should be initialized");
		auto It = Timers->find(Name);
		if (It != Timers->end() && It->second != INVALID_TASK_ID && It->second != LOCKED_TASK_ID)
		{
			if (ClearScheduled)
				Schedule::Get()->ClearTimeout(It->second);
			It->second = INVALID_TASK_ID;
		}
		return Active;
	}
	bool SystemControl::ActivateAndEnqueue() noexcept
	{
		UMutex<std::recursive_mutex> Unique(Sync);
		if (Active || Tasks > 0)
			return false;

		using TimersType = UnorderedMap<String, TaskId>;
		if (!Timers)
			Timers = Memory::New<TimersType>();

		Tasks = 1;
		Active = true;
		return true;
	}
	bool SystemControl::Deactivate() noexcept
	{
		UMutex<std::recursive_mutex> Unique(Sync);
		if (!Active)
			return false;

		auto* Queue = Schedule::Get();
		Active = false;
		if (!Timers)
			return true;

		if (!Timers->empty())
			VI_DEBUG("[sysctl] OK clear timers on %.*s service (timers = %" PRIu64 ")", (int)ServiceName.size(), ServiceName.data(), (uint64_t)Timers->size());
		for (auto& TimerId : *Timers)
			Queue->ClearTimeout(TimerId.second);

		Memory::Delete(Timers);
		return true;
	}
	bool SystemControl::EnqueueIfNone() noexcept
	{
		UMutex<std::recursive_mutex> Unique(Sync);
		if (!Active)
		{
			VI_DEBUG("[sysctl] cancel task on %.*s service: shutdown", (int)ServiceName.size(), ServiceName.data());
			return false;
		}
		else if (Tasks > 0)
			return false;

		++Tasks;
		return true;
	}
	bool SystemControl::Enqueue() noexcept
	{
		UMutex<std::recursive_mutex> Unique(Sync);
		if (!Active)
		{
			VI_DEBUG("[sysctl] cancel task on %.*s service: shutdown", (int)ServiceName.size(), ServiceName.data());
			return false;
		}

		++Tasks;
		return true;
	}
	bool SystemControl::Dequeue() noexcept
	{
		UMutex<std::recursive_mutex> Unique(Sync);
		if (!Tasks)
		{
			VI_DEBUG("[sysctl] finish task on %.*s service: already finalized", (int)ServiceName.size(), ServiceName.data());
			return false;
		}

		--Tasks;
		return Active;
	}
	bool SystemControl::IsActive() noexcept
	{
		return Active;
	}
	bool SystemControl::IsBusy() noexcept
	{
		UMutex<std::recursive_mutex> Unique(Sync);
		return Tasks > 0;
	}

	ServiceControl::ServiceControl() noexcept : ExitCode(0xFFFFFFFF)
	{
		Instance = this;
		BindFatalTermination<Signal::SIG_ABRT>();
		BindFatalTermination<Signal::SIG_FPE>();
		BindFatalTermination<Signal::SIG_ILL>();
		BindFatalTermination<Signal::SIG_SEGV>();
		BindNormalTermination<Signal::SIG_INT>();
		BindNormalTermination<Signal::SIG_TERM>();
	}
	void ServiceControl::Bind(ServiceNode&& Entrypoint) noexcept
	{
		if (Entrypoint.Startup && Entrypoint.Shutdown)
			Services.push_back(std::move(Entrypoint));
	}
	void ServiceControl::Shutdown(int Signal) noexcept
	{
		VI_INFO("[srvctl] service shutdown requested (signal code = %i, state = OK)", Signal);
		Instance = nullptr;
		if (Signal != OS::Process::GetSignalId(Signal::SIG_INT) && Signal != OS::Process::GetSignalId(Signal::SIG_TERM))
			ExitCode = 0x1;
		else
			ExitCode = 0x0;
		Schedule::Get()->Wakeup();
	}
	void ServiceControl::Abort(int Signal) noexcept
	{
		std::cout << "[srvctl] PANIC! service termination requested (signal code " << Signal << ", state = unrecoverable, mode = abort):\n" << ErrorHandling::GetStackTrace(0) << std::endl;
		Instance = nullptr;
		OS::Process::Abort();
	}
	int ServiceControl::Launch() noexcept
	{
		Schedule::Desc Policy;
		Policy.Ping = [this]() { return ExitCode == 0xFFFFFFFF; };
		if (Protocol::Now().User.ComputationThreadsRatio > 0.0)
		{
			auto Threads = OS::CPU::GetQuantityInfo().Logical;
#ifndef VI_CXX20
			Policy.Threads[((size_t)Difficulty::Async)] = (size_t)std::max(std::ceil(Threads * 0.20), 1.0);
#else
			Policy.Threads[((size_t)Difficulty::Async)] = 1;
#endif
			Policy.Threads[((size_t)Difficulty::Sync)] = (size_t)std::max(std::ceil(Threads * Protocol::Now().User.ComputationThreadsRatio), 1.0);
			Policy.Threads[((size_t)Difficulty::Timeout)] = 1;
		}

		VI_INFO("[srvctl] service launch requested (services: %i)", (int)Services.size());
		for (auto& Service : Services)
			Service.Startup();

		Schedule* Queue = Schedule::Get();
		if (!Queue->Start(Policy))
			return -1;

		for (auto& Service : Services)
			Service.Shutdown();

		Queue->Stop();
		while (Queue->Dispatch());
		return 0;
	}
	ServiceControl* ServiceControl::Instance = nullptr;
}