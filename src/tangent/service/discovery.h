#ifndef TAN_SERVICE_DISCOVERY_H
#define TAN_SERVICE_DISCOVERY_H
#include "../kernel/control.h"

namespace tangent
{
	namespace discovery
	{
		class server_node : public reference<server_node>
		{
		protected:
			system_control control_sys;
			uptr<http::server> node;

		public:
			server_node() noexcept;
			~server_node() noexcept;
			void startup();
			void shutdown();
			bool is_active();
			service_control::service_node get_entrypoint();

		private:
			bool headers(http::connection* base, string& content);
			bool options(http::connection* base);
			bool dispatch(http::connection* base);
		};
	}
}
#endif