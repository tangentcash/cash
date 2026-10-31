#include "service/consensus.h"
#include "service/discovery.h"
#include "service/rpc.h"
#include "service/cli.h"
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#endif

using namespace tangent;

int main(int argc, char* argv[])
{
#ifdef _WIN32
	SIZE_T decommit_threshold = 64ull * 1024 * 1024;
	HeapSetInformation(GetProcessHeap(), (HEAP_INFORMATION_CLASS)3 /* HeapDeCommitFreeBlockThreshold */, &decommit_threshold, sizeof(decommit_threshold));
#endif

	auto scope = vitex::runtime();
	auto args = os::process::parse_args(argc, argv, (size_t)args_format::key | (size_t)args_format::key_value);
	auto params = kernel(&args);
	if (args.params.empty() || args.params.front() != "vm")
	{
		consensus::server_node consensus_service;
		discovery::server_node discovery_service;
		rpc::server_node rpc_service = rpc::server_node(&consensus_service);

		service_control control;
		control.bind(consensus_service.get_entrypoint());
		control.bind(discovery_service.get_entrypoint());
		control.bind(rpc_service.get_entrypoint());
		return control.launch();
	}
	else
	{
		cli::interpreter control(args.is_enabled("machine"));
		return control.launch(args, 1, 1);
	}
}