#ifndef TAN_LAYER_CONTROL_H
#define TAN_LAYER_CONTROL_H
#include "../kernel/chain.h"

namespace tangent
{
	struct system_endpoint
	{
		location scheme;
		socket_address address;
		bool secure;

		system_endpoint(const std::string_view& uri);
		bool is_valid() const;
		static string to_uri(const socket_address& address, const std::string_view& protocol = "tcp");
	};

	struct system_control
	{
		unordered_map<string, task_id>* timers;
		std::atomic<bool> active;
		std::recursive_mutex sync;
		std::string_view service_name;

		system_control(const std::string_view& label) noexcept;
		bool lock_timeout(const std::string_view& name);
		bool unlock_timeout(const std::string_view& name);
		bool interval_if_none(const std::string_view& name, uint64_t ms, task_callback&& callback) noexcept;
		bool timeout_if_none(const std::string_view& name, uint64_t ms, task_callback&& callback) noexcept;
		bool upsert_timeout(const std::string_view& name, uint64_t ms, task_callback&& callback) noexcept;
		bool clear_timeout(const std::string_view& name, bool clear_scheduled = false) noexcept;
		bool activate() noexcept;
		bool deactivate() noexcept;
		bool is_active() noexcept;
	};

	struct service_control
	{
	public:
		struct service_node
		{
			std::function<void()> startup;
			std::function<void()> shutdown;
		};

	private:
		static service_control* instance;

	private:
		vector<service_node> services;
		std::atomic<int> exit_code;

	public:
		service_control() noexcept;
		void bind(service_node&& entrypoint) noexcept;
		void shutdown(int signal) noexcept;
		void abort(int signal) noexcept;
		int launch() noexcept;

	private:
		template <signal_code type>
		static void bind_normal_termination()
		{
			os::process::bind_signal(type, [](int signal)
			{
				os::process::rebind_signal(type);
				if (instance != nullptr)
					instance->shutdown(signal);
			});
		}
		template <signal_code type>
		static void bind_fatal_termination()
		{
			os::process::bind_signal(type, [](int signal)
			{
				os::process::rebind_signal(type);
				if (instance != nullptr)
					instance->abort(signal);
			});
		}
	};
}
#endif