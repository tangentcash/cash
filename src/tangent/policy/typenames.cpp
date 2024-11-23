#include "typenames.h"
#include <array>

namespace Tangent
{
	uint32_t Types::TypeOf(const std::string_view& Name)
	{
		VI_ASSERT(!Name.empty(), "typename should not be empty");
		static std::array<std::string_view, 43> Types =
		{
			{
				std::string_view("account_sequence"),
				std::string_view("account_work"),
				std::string_view("account_program"),
				std::string_view("account_storage"),
				std::string_view("account_reward"),
				std::string_view("account_derivation"),
				std::string_view("account_balance"),
				std::string_view("account_contribution"),
				std::string_view("witness_program"),
				std::string_view("witness_event"),
				std::string_view("witness_address"),
				std::string_view("witness_transaction"),
				std::string_view("commitment"),
				std::string_view("transfer"),
				std::string_view("omnitransfer"),
				std::string_view("deployment"),
				std::string_view("invocation"),
				std::string_view("withdrawal"),
				std::string_view("rollup"),
				std::string_view("account"),
				std::string_view("replay"),
				std::string_view("claim"),
				std::string_view("contribution_allocation"),
				std::string_view("contribution_activation"),
				std::string_view("contribution_deallocation"),
				std::string_view("contribution_deactivation"),
				std::string_view("contribution_adjustment"),
				std::string_view("contribution_allowance"),
				std::string_view("contribution_migration"),
				std::string_view("block_transaction"),
				std::string_view("block"),
				std::string_view("block_proof"),
				std::string_view("receipt"),
				std::string_view("wallet"),
				std::string_view("edge"),
				std::string_view("oracle_master_wallet"),
				std::string_view("oracle_derived_verifying_wallet"),
				std::string_view("oracle_derived_signing_wallet"),
				std::string_view("oracle_verifiable_message"),
				std::string_view("oracle_incoming_transaction"),
				std::string_view("oracle_outgoing_transaction"),
				std::string_view("oracle_index_address"),
				std::string_view("oracle_index_utxo"),
			}
		};

		for (size_t i = 0; i < Types.size(); i++)
		{
			auto& Type = Types[i];
			if (Type.front() == Name.front() && Type == Name)
				return (uint32_t)(i + 1);
		}

		return Algorithm::Encoding::TypeOf(Name);
	}
}