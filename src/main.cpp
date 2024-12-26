#include "tangent/layer/p2p.h"
#include "tangent/layer/rpc.h"
#include "tangent/layer/nds.h"

using namespace Tangent;

int main0()
{
	Vitex::Runtime Scope;
	Protocol Params;
	ServiceControl Control;

	UPtr<P2P::ServerNode> Consensus = new P2P::ServerNode();
	Control.Bind(Consensus->GetEntrypoint());

	UPtr<NDS::ServerNode> Discovery = new NDS::ServerNode();
	Control.Bind(Discovery->GetEntrypoint());

	UPtr<RPC::ServerNode> Interface = new RPC::ServerNode(*Consensus);
	Control.Bind(Interface->GetEntrypoint());

	return Control.Launch();
}