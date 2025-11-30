#include "tangent/entrypoints.hpp"
#include <vitex/vitex.h>

using namespace tangent;

int main(int argc, char* argv[])
{
	auto scope = vitex::runtime();
	auto environment = os::process::parse_args(argc, argv, (size_t)args_format::key | (size_t)args_format::key_value);
	return !environment.params.empty() && environment.params.front() == "vm" ? entrypoints::script(environment) : entrypoints::node(environment);
}