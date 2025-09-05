#include "control.h"
#include <iostream>
#define LOCKED_TASK_ID std::numeric_limits<uint64_t>::max()

namespace tangent
{
	system_endpoint::system_endpoint(const std::string_view& uri) : scheme(uri), secure(false)
	{
		if (scheme.hostname.empty())
			return;

		socket_address primary_candidate = socket_address(scheme.hostname, scheme.port > 0 ? scheme.port : protocol::now().user.consensus.port);
		if (!primary_candidate.is_valid())
		{
			auto secondary_candidate = dns::get()->lookup(scheme.hostname, to_string(scheme.port > 0 ? scheme.port : protocol::now().user.consensus.port), dns_type::listen);
			if (!secondary_candidate)
				return;

			auto ip_address = secondary_candidate->get_ip_address();
			if (!ip_address)
				return;

			scheme.hostname = std::move(*ip_address);
		}

		if (scheme.protocol == "tcp" || scheme.protocol == "tcps")
			address = socket_address(scheme.hostname, scheme.port > 0 ? scheme.port : protocol::now().user.consensus.port);
		else if (scheme.protocol == "http" || scheme.protocol == "https")
			address = socket_address(scheme.hostname, scheme.port > 0 ? scheme.port : protocol::now().user.discovery.port);
		else if (scheme.protocol == "rpc" || scheme.protocol == "rpcs")
			address = socket_address(scheme.hostname, scheme.port > 0 ? scheme.port : protocol::now().user.rpc.port);
		secure = address.is_valid() && scheme.protocol.back() == 's';
	}
	bool system_endpoint::is_valid() const
	{
		return address.is_valid() && !scheme.hostname.empty() && !scheme.protocol.empty() && (scheme.protocol == "tcp" || scheme.protocol == "tcps" || scheme.protocol == "http" || scheme.protocol == "https" || scheme.protocol == "rpc" || scheme.protocol == "rpcs");
	}
	string system_endpoint::to_uri(const socket_address& address, const std::string_view& protocol)
	{
		string URI = string(protocol);
		URI.append("://");
		URI.append(address.get_ip_address().or_else("[bad_address]"));

		auto ip_port = address.get_ip_port();
		if (ip_port)
			URI.append(":").append(to_string(*ip_port));

		return URI;
	}

	system_task::system_task(string&& new_id, system_control* new_control) : id(std::move(new_id)), control(new_control)
	{
	}
	system_task::system_task(system_task&& other) noexcept : id(std::move(other.id)), control(other.control)
	{
		other.control = nullptr;
	}
	system_task::~system_task() noexcept
	{
		if (control != nullptr)
		{
			control->clear_task(id);
			control = nullptr;
		}
	}
	system_task& system_task::operator= (system_task&& other) noexcept
	{
		if (this == &other)
			return *this;

		this->~system_task();
		id = std::move(other.id);
		control = other.control;
		other.control = nullptr;
		return *this;
	}

	system_control::system_control(const std::string_view& label) noexcept : timers(nullptr), tasks(nullptr), active(false), service_name(label.empty() ? "unknown" : label)
	{
	}
	bool system_control::lock_timeout(const std::string_view& name)
	{
		umutex<std::recursive_mutex> unique(sync);
		if (!active)
		{
			if (protocol::now().user.logs.control_logging)
				VI_INFO("cancel %.*s lock on %.*s service: shutdown", (int)name.size(), name.data(), (int)service_name.size(), service_name.data());
			return false;
		}

		VI_ASSERT(timers != nullptr, "timers should be initialized");
		if (protocol::now().user.logs.control_logging && timers->find(key_lookup_cast(name)) == timers->end())
			VI_INFO("OK spawn %.*s locked task on %.*s service (mode: lock-timeout)", (int)name.size(), name.data(), (int)service_name.size(), service_name.data());

		auto& timer = (*timers)[string(name)];
		if (timer != INVALID_TASK_ID)
		{
			if (protocol::now().user.logs.control_logging)
				VI_INFO("cancel %.*s lock on %.*s service: in use", (int)name.size(), name.data(), (int)service_name.size(), service_name.data());
			return false;
		}

		timer = LOCKED_TASK_ID;
		return true;
	}
	bool system_control::unlock_timeout(const std::string_view& name)
	{
		umutex<std::recursive_mutex> unique(sync);
		if (!active)
		{
			if (protocol::now().user.logs.control_logging)
				VI_INFO("cancel %.*s unlock on %.*s service: shutdown", (int)name.size(), name.data(), (int)service_name.size(), service_name.data());
			return false;
		}

		VI_ASSERT(timers != nullptr, "timers should be initialized");
		if (timers->find(key_lookup_cast(name)) == timers->end())
		{
			if (protocol::now().user.logs.control_logging)
				VI_INFO("cancel %.*s unlock on %.*s service: not locked", (int)name.size(), name.data(), (int)service_name.size(), service_name.data());
			return false;
		}

		auto& timer = (*timers)[string(name)];
		if (timer == LOCKED_TASK_ID)
			timer = INVALID_TASK_ID;
		return true;
	}
	bool system_control::task_if_none(const std::string_view& name, std::function<void(system_task&&)>&& callback) noexcept
	{
		umutex<std::recursive_mutex> unique(sync);
		if (!active)
		{
			if (protocol::now().user.logs.control_logging)
				VI_INFO("cancel %.*s task on %.*s service: shutdown", (int)name.size(), name.data(), (int)service_name.size(), service_name.data());
			return false;
		}

		VI_ASSERT(tasks != nullptr, "tasks should be initialized");
		if (protocol::now().user.logs.control_logging && tasks->find(key_lookup_cast(name)) == tasks->end())
			VI_INFO("OK spawn %.*s task on %.*s service (mode: task)", (int)name.size(), name.data(), (int)service_name.size(), service_name.data());

		auto id = string(name);
		auto& task = (*tasks)[id];
		if (task)
			return false;

		task = schedule::get()->set_task([this, id = std::move(id), callback = std::move(callback)]() mutable { callback(system_task(std::move(id), this)); });
		if (task)
			return true;

		if (protocol::now().user.logs.control_logging)
			VI_INFO("cancel %.*s task on %.*s service: inactive", (int)name.size(), name.data(), (int)service_name.size(), service_name.data());
		return false;
	}
	bool system_control::async_task_if_none(const std::string_view& name, std::function<promise<void>()>&& callback) noexcept
	{
		umutex<std::recursive_mutex> unique(sync);
		if (!active)
		{
			if (protocol::now().user.logs.control_logging)
				VI_INFO("cancel %.*s async task on %.*s service: shutdown", (int)name.size(), name.data(), (int)service_name.size(), service_name.data());
			return false;
		}

		VI_ASSERT(tasks != nullptr, "tasks should be initialized");
		if (protocol::now().user.logs.control_logging && tasks->find(key_lookup_cast(name)) == tasks->end())
			VI_INFO("OK spawn %.*s async task on %.*s service (mode: async task)", (int)name.size(), name.data(), (int)service_name.size(), service_name.data());

		auto id = string(name);
		auto& task = (*tasks)[id];
		if (task)
			return false;

		task = schedule::get()->set_task([this, id = std::move(id), callback = std::move(callback)]() mutable
		{
			coasync<void>([this, callback = std::move(callback)]() mutable -> promise<void>
			{
				coreturn coawait(callback());
			}).when([this, id = std::move(id)]() mutable
			{
				clear_task(id);
			});
		});
		if (task)
			return true;

		if (protocol::now().user.logs.control_logging)
			VI_INFO("cancel %.*s async task on %.*s service: inactive", (int)name.size(), name.data(), (int)service_name.size(), service_name.data());
		return false;
	}
	bool system_control::interval_if_none(const std::string_view& name, uint64_t ms, task_callback&& callback) noexcept
	{
		umutex<std::recursive_mutex> unique(sync);
		if (!active)
		{
			if (protocol::now().user.logs.control_logging)
				VI_INFO("cancel %.*s interval on %.*s service: shutdown", (int)name.size(), name.data(), (int)service_name.size(), service_name.data());
			return false;
		}

		VI_ASSERT(timers != nullptr, "timers should be initialized");
		if (protocol::now().user.logs.control_logging && timers->find(key_lookup_cast(name)) == timers->end())
			VI_INFO("OK spawn %.*s task on %.*s service (mode: interval, delay: %" PRIu64 " ms)", (int)name.size(), name.data(), (int)service_name.size(), service_name.data(), ms);

		auto& timer = (*timers)[string(name)];
		if (timer != INVALID_TASK_ID || timer == LOCKED_TASK_ID)
			return false;

		timer = schedule::get()->set_interval(ms, std::move(callback));
		if (timer != INVALID_TASK_ID)
			return true;

		if (protocol::now().user.logs.control_logging)
			VI_INFO("cancel %.*s interval on %.*s service: inactive", (int)name.size(), name.data(), (int)service_name.size(), service_name.data());
		return false;
	}
	bool system_control::timeout_if_none(const std::string_view& name, uint64_t ms, task_callback&& callback) noexcept
	{
		umutex<std::recursive_mutex> unique(sync);
		if (!active)
		{
			if (protocol::now().user.logs.control_logging)
			VI_INFO("cancel %.*s timeout on %.*s service: shutdown", (int)name.size(), name.data(), (int)service_name.size(), service_name.data());
			return false;
		}

		VI_ASSERT(timers != nullptr, "timers should be initialized");
		if (protocol::now().user.logs.control_logging && timers->find(key_lookup_cast(name)) == timers->end())
			VI_INFO("OK spawn %.*s task on %.*s service (mode: timeout, delay: %" PRIu64 " ms)", (int)name.size(), name.data(), (int)service_name.size(), service_name.data(), ms);

		auto& timer = (*timers)[string(name)];
		if (timer != INVALID_TASK_ID || timer == LOCKED_TASK_ID)
			return false;

		timer = schedule::get()->set_timeout(ms, std::move(callback));
		if (timer != INVALID_TASK_ID)
			return true;

		if (protocol::now().user.logs.control_logging)
			VI_INFO("cancel %.*s timeout on %.*s service: inactive", (int)name.size(), name.data(), (int)service_name.size(), service_name.data());
		return false;
	}
	bool system_control::upsert_timeout(const std::string_view& name, uint64_t ms, task_callback&& callback) noexcept
	{
		umutex<std::recursive_mutex> unique(sync);
		if (!active)
		{
			if (protocol::now().user.logs.control_logging)
			VI_INFO("cancel %.*s timeout on %.*s service: shutdown", (int)name.size(), name.data(), (int)service_name.size(), service_name.data());
			return false;
		}

		VI_ASSERT(timers != nullptr, "timers should be initialized");
		if (protocol::now().user.logs.control_logging && timers->find(key_lookup_cast(name)) == timers->end())
			VI_INFO("OK spawn %.*s task on %.*s service (mode: upsert-timeout, delay: %" PRIu64 " ms)", (int)name.size(), name.data(), (int)service_name.size(), service_name.data(), ms);

		auto& timer = (*timers)[string(name)];
		if (timer == LOCKED_TASK_ID)
			return false;

		timer = schedule::get()->set_timeout(ms, std::move(callback));
		if (timer != INVALID_TASK_ID)
			return true;

		if (protocol::now().user.logs.control_logging)
			VI_INFO("cancel %.*s timeout on %.*s service: inactive", (int)name.size(), name.data(), (int)service_name.size(), service_name.data());
		return false;
	}
	bool system_control::clear_timeout(const std::string_view& name, bool clear_scheduled) noexcept
	{
		umutex<std::recursive_mutex> unique(sync);
		if (!active)
			return false;

		VI_ASSERT(timers != nullptr, "timers should be initialized");
		auto it = timers->find(name);
		if (it != timers->end() && it->second != INVALID_TASK_ID && it->second != LOCKED_TASK_ID)
		{
			if (clear_scheduled)
				schedule::get()->clear_timeout(it->second);
			it->second = INVALID_TASK_ID;
		}
		return active;
	}
	bool system_control::clear_task(const std::string_view& name) noexcept
	{
		umutex<std::recursive_mutex> unique(sync);
		VI_ASSERT(tasks != nullptr, "tasks should be initialized");
		auto it = tasks->find(key_lookup_cast(name));
		if (it != tasks->end())
			it->second = false;
		return true;
	}
	bool system_control::activate() noexcept
	{
		umutex<std::recursive_mutex> unique(sync);
		if (active)
			return false;

		if (!timers)
			timers = memory::init<unordered_map<string, task_id>>();
		if (!tasks)
			tasks = memory::init<unordered_map<string, bool>>();

		active = true;
		return true;
	}
	bool system_control::deactivate(bool fully) noexcept
	{
		umutex<std::recursive_mutex> unique(sync);
		auto* queue = schedule::get();
		active = false;

		if (timers != nullptr)
		{
			for (auto& timer_id : *timers)
				queue->clear_timeout(timer_id.second);
			if (protocol::now().user.logs.control_logging && !timers->empty())
				VI_INFO("OK clear timers on %.*s service (timers: %" PRIu64 ")", (int)service_name.size(), service_name.data(), (uint64_t)timers->size());
			if (fully)
				memory::deinit(timers);
			else
				timers->clear();
		}
		
		if (fully && tasks != nullptr)
		{
			auto time = date_time().milliseconds();
			auto finalized_tasks = tasks->size();
			unordered_set<string> pending;
		retry:
			for (auto& [id, active] : *tasks)
			{
				if (active)
					pending.insert(id);
			}

			bool requires_retry = !pending.empty();
			unique.unlock();
			while (!pending.empty())
			{
				auto it = pending.begin();
				bool requires_warning = false;
				while (has_task(*it))
				{
					std::this_thread::sleep_for(std::chrono::milliseconds(1));
					if (requires_warning && protocol::now().user.logs.control_logging && date_time().milliseconds() - time > 3000)
					{
						VI_WARN("task %s stall on %.*s service", it->c_str(), (int)service_name.size(), service_name.data());
						requires_warning = false;
					}
				}
				pending.erase(it);
			}

			unique.lock();
			if (requires_retry)
				goto retry;

			if (finalized_tasks > 0 && protocol::now().user.logs.control_logging)
				VI_INFO("OK finalized tasks on %.*s service (tasks: %" PRIu64 ")", (int)service_name.size(), service_name.data(), (uint64_t)finalized_tasks);
			memory::deinit(tasks);
		}

		return true;
	}
	bool system_control::has_task(const std::string_view& name) noexcept
	{
		umutex<std::recursive_mutex> unique(sync);
		VI_ASSERT(tasks != nullptr, "tasks should be initialized");
		auto it = tasks->find(key_lookup_cast(name));
		return it != tasks->end() && it->second;
	}
	bool system_control::is_active() noexcept
	{
		return active;
	}

	service_control::service_control() noexcept : exit_code(0xFFFFFFFF)
	{
		instance = this;
		bind_fatal_termination<signal_code::SIG_ABRT>();
		bind_fatal_termination<signal_code::SIG_FPE>();
		bind_fatal_termination<signal_code::SIG_ILL>();
		bind_fatal_termination<signal_code::SIG_SEGV>();
		bind_normal_termination<signal_code::SIG_INT>();
		bind_normal_termination<signal_code::SIG_TERM>();
	}
	void service_control::bind(service_node&& entrypoint) noexcept
	{
		if (entrypoint.startup && entrypoint.shutdown)
			services.push_back(std::move(entrypoint));
	}
	void service_control::shutdown(int signal) noexcept
	{
		if (protocol::now().user.logs.control_logging)
			VI_INFO("service shutdown (signal code: %i, state = OK)", signal);

		instance = nullptr;
		if (signal != os::process::get_signal_id(signal_code::SIG_INT) && signal != os::process::get_signal_id(signal_code::SIG_TERM))
			exit_code = 0x1;
		else
			exit_code = 0x0;
		schedule::get()->wakeup();
	}
	void service_control::abort(int signal) noexcept
	{
		std::cout << "[srvctl] PANIC! service termination (signal code " << signal << ", state = unrecoverable, mode: abort):\n" << error_handling::get_stack_trace(0) << std::endl;
		instance = nullptr;
		os::process::abort();
	}
	int service_control::launch() noexcept
	{
		schedule::desc policy;
		policy.ping = [this]() { return exit_code == 0xFFFFFFFF; };
		if (protocol::now().user.storage.computation_threads_ratio > 0.0)
		{
			auto threads = os::hw::get_quantity_info().logical;
#ifndef VI_CXX20
			policy.threads[((size_t)difficulty::async)] = (size_t)std::max(std::ceil(threads * 0.20), 1.0);
#else
			policy.threads[((size_t)difficulty::async)] = 1;
#endif
			policy.threads[((size_t)difficulty::sync)] = (size_t)std::max(std::ceil(threads * protocol::now().user.storage.computation_threads_ratio), 1.0);
			policy.threads[((size_t)difficulty::timeout)] = 1;
		}

		if (protocol::now().user.logs.control_logging)
			VI_INFO("service launch (services: %i)", (int)services.size());

		for (auto& service : services)
			service.startup();

		error_handling::set_flag(log_option::async, true);
		schedule* queue = schedule::get();
		if (!queue->start(policy))
			return -1;

		error_handling::set_flag(log_option::async, false);
		for (auto& service : services)
			service.shutdown();

		queue->stop();
		if (multiplexer::has_instance())
			multiplexer::get()->shutdown();

		while (queue->dispatch());
		return 0;
	}
	service_control* service_control::instance = nullptr;
}