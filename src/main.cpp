#include "tangent/validator/entrypoints.hpp"

using namespace tangent;

int main(int argc, char* argv[])
{
	auto scope = vitex::runtime();
	auto environment = os::process::parse_args(argc, argv, (size_t)args_format::key | (size_t)args_format::key_value);
	return !environment.params.empty() && environment.params.front() == "svm" ? entrypoints::svm(environment) : entrypoints::node(environment);
}