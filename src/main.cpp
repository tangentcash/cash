#include "tangent/layer/p2p.h"
#include "tangent/layer/rpc.h"

using namespace Tangent;

int main0()
{
	Vitex::Runtime Scope;
	Protocol Params;

	UPtr<P2P::ServerNode> Consensus = new P2P::ServerNode();
	UPtr<RPC::ServerNode> Interface = new RPC::ServerNode(*Consensus);

	ServiceControl Control;
	Control.Bind(Consensus->GetEntrypoint());
	Control.Bind(Interface->GetEntrypoint());
	return Control.Launch();
}