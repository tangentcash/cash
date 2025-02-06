#include "tangent/validator/service/nss.h"
#include "tangent/validator/service/nds.h"
#include "tangent/validator/service/p2p.h"
#include "tangent/validator/service/rpc.h"

using namespace Tangent;

int main(int argc, char* argv[])
{
	Vitex::Runtime Scope;
	Protocol Params = Protocol(argc > 1 ? argv[1] : TAN_CONFIG_PATH);
	NDS::ServerNode Discovery;
	P2P::ServerNode Consensus;
	NSS::ServerNode& Synchronization = *NSS::ServerNode::Get();
	RPC::ServerNode Interface = RPC::ServerNode(&Consensus);

	ServiceControl Control;
	Control.Bind(Discovery.GetEntrypoint());
	Control.Bind(Consensus.GetEntrypoint());
	Control.Bind(Synchronization.GetEntrypoint());
	Control.Bind(Interface.GetEntrypoint());
	return Control.Launch();
}