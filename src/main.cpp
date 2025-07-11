#include "tangent/validator/service/nss.h"
#include "tangent/validator/service/nds.h"
#include "tangent/validator/service/p2p.h"
#include "tangent/validator/service/rpc.h"

using namespace tangent;

int svm(const inline_args& args)
{
	/* TODO: svm program debugger and packer */
}
int server(const inline_args& args)
{
	nds::server_node discovery;
	p2p::server_node consensus;
	nss::server_node& synchronization = *nss::server_node::get();
	rpc::server_node interfaces = rpc::server_node(&consensus);

	service_control control;
	control.bind(discovery.get_entrypoint());
	control.bind(consensus.get_entrypoint());
	control.bind(synchronization.get_entrypoint());
	control.bind(interfaces.get_entrypoint());
	return control.launch();
}
int main(int argc, char* argv[])
{
	vitex::runtime scope;
	inline_args environment = os::process::parse_args(argc, argv, (size_t)args_format::key_value);
	protocol params = protocol(environment);
	return environment.has("svm") ? svm(environment) : server(environment);
}