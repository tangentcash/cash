#ifndef TAN_LAYER_CONTROL_H
#define TAN_LAYER_CONTROL_H
#include "../kernel/chain.h"

namespace tangent
{
	struct system_control;

	struct system_endpoint
	{
		location scheme;
		socket_address address;
		bool secure;

		system_endpoint(const std::string_view& uri, const std::string_view& parent_uri = std::string_view());
		bool is_valid() const;
		static string to_uri(const socket_address& address, const std::string_view& protocol = "tcp");
	};

	struct system_task
	{
		string id;
		system_control* control;

		system_task(string&& new_id, system_control* new_control);
		system_task(const system_task&) = delete;
		system_task(system_task&& other) noexcept;
		~system_task() noexcept;
		system_task& operator= (const system_task&) = delete;
		system_task& operator= (system_task&& other) noexcept;
	};

	struct system_control
	{
		unordered_map<string, task_id>* timers;
		unordered_map<string, bool>* tasks;
		std::atomic<bool> active;
		std::recursive_mutex sync;
		std::string_view service_name;

		system_control(const std::string_view& label) noexcept;
		bool lock_timeout(const std::string_view& name);
		bool unlock_timeout(const std::string_view& name);
		bool task_if_none(const std::string_view& name, std::function<void(system_task&&)>&& callback) noexcept;
		bool async_task_if_none(const std::string_view& name, std::function<promise<void>()>&& callback) noexcept;
		bool interval_if_none(const std::string_view& name, uint64_t ms, task_callback&& callback) noexcept;
		bool timeout_if_none(const std::string_view& name, uint64_t ms, task_callback&& callback) noexcept;
		bool upsert_timeout(const std::string_view& name, uint64_t ms, task_callback&& callback) noexcept;
		bool clear_timeout(const std::string_view& name, bool clear_scheduled = false) noexcept;
		bool clear_task(const std::string_view& name) noexcept;
		bool activate() noexcept;
		bool deactivate(bool fully = true) noexcept;
		bool has_task(const std::string_view& name) noexcept;
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