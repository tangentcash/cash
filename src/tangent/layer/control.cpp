#include "control.h"
#include <iostream>
#define LOCKED_TASK_ID std::numeric_limits<uint64_t>::max()

namespace tangent
{
	system_endpoint::system_endpoint(const std::string_view& URI) : scheme(URI), secure(false)
	{
		if (scheme.hostname.empty())
			return;

		socket_address primary_candidate = socket_address(scheme.hostname, scheme.port > 0 ? scheme.port : protocol::now().user.p2p.port);
		if (!primary_candidate.is_valid())
		{
			auto secondary_candidate = dns::get()->lookup(scheme.hostname, to_string(scheme.port > 0 ? scheme.port : protocol::now().user.p2p.port), dns_type::listen);
			if (!secondary_candidate)
				return;

			auto ip_address = secondary_candidate->get_ip_address();
			if (!ip_address)
				return;

			scheme.hostname = std::move(*ip_address);
		}

		if (scheme.protocol == "tcp" || scheme.protocol == "tcps")
			address = socket_address(scheme.hostname, scheme.port > 0 ? scheme.port : protocol::now().user.p2p.port);
		else if (scheme.protocol == "http" || scheme.protocol == "https")
			address = socket_address(scheme.hostname, scheme.port > 0 ? scheme.port : protocol::now().user.nds.port);
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

	system_control::system_control(const std::string_view& label) noexcept : timers(nullptr), active(false), service_name(label.empty() ? "unknown" : label)
	{
	}
	bool system_control::lock_timeout(const std::string_view& name)
	{
		umutex<std::recursive_mutex> unique(sync);
		if (!active)
		{
			VI_DEBUG("cancel %.*s lock on %.*s service: shutdown", (int)name.size(), name.data(), (int)service_name.size(), service_name.data());
			return false;
		}

		VI_ASSERT(timers != nullptr, "timers should be initialized");
		if (timers->find(key_lookup_cast(name)) == timers->end())
			VI_DEBUG("OK spawn %.*s locked task on %.*s service (mode = lock-timeout)", (int)name.size(), name.data(), (int)service_name.size(), service_name.data());

		auto& timer = (*timers)[string(name)];
		if (timer != INVALID_TASK_ID)
		{
			VI_DEBUG("cancel %.*s lock on %.*s service: in use", (int)name.size(), name.data(), (int)service_name.size(), service_name.data());
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
			VI_DEBUG("cancel %.*s unlock on %.*s service: shutdown", (int)name.size(), name.data(), (int)service_name.size(), service_name.data());
			return false;
		}

		VI_ASSERT(timers != nullptr, "timers should be initialized");
		if (timers->find(key_lookup_cast(name)) == timers->end())
		{
			VI_DEBUG("cancel %.*s unlock on %.*s service: not locked", (int)name.size(), name.data(), (int)service_name.size(), service_name.data());
			return false;
		}

		auto& timer = (*timers)[string(name)];
		if (timer == LOCKED_TASK_ID)
			timer = INVALID_TASK_ID;
		return true;
	}
	bool system_control::interval_if_none(const std::string_view& name, uint64_t ms, task_callback&& callback) noexcept
	{
		umutex<std::recursive_mutex> unique(sync);
		if (!active)
		{
			VI_DEBUG("cancel %.*s interval on %.*s service: shutdown", (int)name.size(), name.data(), (int)service_name.size(), service_name.data());
			return false;
		}

		VI_ASSERT(timers != nullptr, "timers should be initialized");
		if (timers->find(key_lookup_cast(name)) == timers->end())
			VI_DEBUG("OK spawn %.*s task on %.*s service (mode = interval, delay = %" PRIu64 " ms)", (int)name.size(), name.data(), (int)service_name.size(), service_name.data(), ms);

		auto& timer = (*timers)[string(name)];
		if (timer != INVALID_TASK_ID || timer == LOCKED_TASK_ID)
			return false;

		timer = schedule::get()->set_interval(ms, std::move(callback));
		if (timer != INVALID_TASK_ID)
			return true;

		VI_DEBUG("cancel %.*s interval on %.*s service: inactive", (int)name.size(), name.data(), (int)service_name.size(), service_name.data());
		return false;
	}
	bool system_control::timeout_if_none(const std::string_view& name, uint64_t ms, task_callback&& callback) noexcept
	{
		umutex<std::recursive_mutex> unique(sync);
		if (!active)
		{
			VI_DEBUG("cancel %.*s timeout on %.*s service: shutdown", (int)name.size(), name.data(), (int)service_name.size(), service_name.data());
			return false;
		}

		VI_ASSERT(timers != nullptr, "timers should be initialized");
		if (timers->find(key_lookup_cast(name)) == timers->end())
			VI_DEBUG("OK spawn %.*s task on %.*s service (mode = timeout, delay = %" PRIu64 " ms)", (int)name.size(), name.data(), (int)service_name.size(), service_name.data(), ms);

		auto& timer = (*timers)[string(name)];
		if (timer != INVALID_TASK_ID || timer == LOCKED_TASK_ID)
			return false;

		timer = schedule::get()->set_timeout(ms, std::move(callback));
		if (timer != INVALID_TASK_ID)
			return true;

		VI_DEBUG("cancel %.*s timeout on %.*s service: inactive", (int)name.size(), name.data(), (int)service_name.size(), service_name.data());
		return false;
	}
	bool system_control::upsert_timeout(const std::string_view& name, uint64_t ms, task_callback&& callback) noexcept
	{
		umutex<std::recursive_mutex> unique(sync);
		if (!active)
		{
			VI_DEBUG("cancel %.*s timeout on %.*s service: shutdown", (int)name.size(), name.data(), (int)service_name.size(), service_name.data());
			return false;
		}

		VI_ASSERT(timers != nullptr, "timers should be initialized");
		if (timers->find(key_lookup_cast(name)) == timers->end())
			VI_DEBUG("OK spawn %.*s task on %.*s service (mode = upsert-timeout, delay = %" PRIu64 " ms)", (int)name.size(), name.data(), (int)service_name.size(), service_name.data(), ms);

		auto& timer = (*timers)[string(name)];
		if (timer == LOCKED_TASK_ID)
			return false;

		timer = schedule::get()->set_timeout(ms, std::move(callback));
		if (timer != INVALID_TASK_ID)
			return true;

		VI_DEBUG("cancel %.*s timeout on %.*s service: inactive", (int)name.size(), name.data(), (int)service_name.size(), service_name.data());
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
	bool system_control::activate() noexcept
	{
		umutex<std::recursive_mutex> unique(sync);
		if (active)
			return false;

		using timers_type = unordered_map<string, task_id>;
		if (!timers)
			timers = memory::init<timers_type>();

		active = true;
		return true;
	}
	bool system_control::deactivate() noexcept
	{
		umutex<std::recursive_mutex> unique(sync);
		if (!active)
			return false;

		auto* queue = schedule::get();
		active = false;
		if (!timers)
			return true;

		if (!timers->empty())
			VI_DEBUG("OK clear timers on %.*s service (timers = %" PRIu64 ")", (int)service_name.size(), service_name.data(), (uint64_t)timers->size());
		for (auto& timer_id : *timers)
			queue->clear_timeout(timer_id.second);

		memory::deinit(timers);
		return true;
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
		VI_INFO("service shutdown (signal code = %i, state = OK)", signal);
		instance = nullptr;
		if (signal != os::process::get_signal_id(signal_code::SIG_INT) && signal != os::process::get_signal_id(signal_code::SIG_TERM))
			exit_code = 0x1;
		else
			exit_code = 0x0;
		schedule::get()->wakeup();
	}
	void service_control::abort(int signal) noexcept
	{
		std::cout << "[srvctl] PANIC! service termination (signal code " << signal << ", state = unrecoverable, mode = abort):\n" << error_handling::get_stack_trace(0) << std::endl;
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