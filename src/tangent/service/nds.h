#ifndef TAN_LAYER_NDS_H
#define TAN_LAYER_NDS_H
#include "../kernel/chain.h"

namespace Tangent
{
	namespace NDS
	{
		class ServerNode : public Reference<ServerNode>
		{
		protected:
			SystemControl ControlSys;
			UPtr<HTTP::Server> Node;

		public:
			ServerNode() noexcept;
			~ServerNode() noexcept;
			void Startup();
			void Shutdown();
			bool IsActive();
			ServiceControl::ServiceNode GetEntrypoint();

		private:
			bool Headers(HTTP::Connection* Base, String& Content);
			bool Options(HTTP::Connection* Base);
			bool Dispatch(HTTP::Connection* Base);
		};
	}
}
#endif