#ifndef TAN_POLICY_TYPENAMES_H
#define TAN_POLICY_TYPENAMES_H
#include "../kernel/algorithm.h"

namespace Tangent
{
	class Types
	{
	public:
		static uint32_t TypeOf(const std::string_view& Name);
	};
}
#endif