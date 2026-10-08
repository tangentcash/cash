mapping<string, real320> escrow;
mapping<string, real320> reserved;
mapping<string, real320> recorded;
mapping<string, uint> flags;
class transfer_witness
{
    string to0 = "";
    string to1 = "";
    real320 first = real320(0);
    real320 second = real320(0);
    real320 balance0 = real320(0);
    real320 balance1 = real320(0);
}
varying<transfer_witness> transfer0;
void construct(pmut@)
{
}
void arm_withdraw(pmut@, const string&in dest)
{
	escrow.insert(dest, tx::to().balance_of(tx::asset()));
	flags.insert("armed", 1);
}
void allow_call(pmut@)
{
	flags.insert("allow_call", 1);
}
void allow_transfer(pmut@)
{
	flags.insert("allow_transfer", 1);
}
void ping(pmut@)
{
	flags.insert("pinged", 1);
}
void delegate(pmut@)
{
	require(tx::function() == "delegate");
	require(!tx::paid());
	require(tx::delegate::from() == tx::from());
	if (tx::delegate::type() == tx::withdraw)
	{
		string dest = tx::delegate::address(0);
		if (dest == "0x00000000000000000000000000000000000000b0")
		{
			tx::delegate::address(1);
			require(false);
		}
		require(tx::delegate::function() == "");
		require(tx::delegate::payments() == 1);
		require(tx::delegate::asset(0) == tx::asset());
		real320 amount = tx::delegate::amount(0);
		require(amount.positive());
		require(escrow.has(dest));
		require(amount <= escrow[dest]);
		recorded.insert(dest, tx::to().balance_of(tx::asset()));
		reserved.insert(dest, amount);
		escrow.insert(dest, real320(0));
	}
	else if (tx::delegate::type() == tx::call)
	{
		require(flags.has("allow_call") && flags["allow_call"] == 1);
		require(tx::delegate::to() == tx::to());
		require(tx::delegate::function() == "ping");
		require(tx::delegate::payments() == 0);
		require(!tx::delegate::paid());
		flags.insert("approved_call", 1);
	}
	else if (tx::delegate::type() == tx::transfer)
	{
		require(flags.has("allow_transfer") && flags["allow_transfer"] == 1);
		require(tx::delegate::payments() == 2);
		require(tx::delegate::asset(0) == tx::asset());
		require(tx::delegate::asset(1) == tx::asset());
		transfer_witness witness = transfer0.empty() ? transfer_witness() : transfer0.ref;
		witness.to0 = tx::delegate::address(0);
		witness.to1 = tx::delegate::address(1);
		witness.first = tx::delegate::amount(0);
		witness.second = tx::delegate::amount(1);
		require(witness.first.positive() && witness.second.positive());
		require(witness.first + witness.second == tx::to().balance_of(tx::asset()));
		witness.balance0 = address(witness.to0).balance_of(tx::asset());
		witness.balance1 = address(witness.to1).balance_of(tx::asset());
		transfer0 = witness;
		flags.insert("approved_transfer", 1);
	}
	else
		require(false);
}
void verify_withdraw(pmut@, const string&in dest, const real320&in fee)
{
	require(escrow.has(dest));
	require(escrow[dest] == real320(0));
	require(recorded.has(dest) && reserved.has(dest));
	require(tx::to().balance_of(tx::asset()) == recorded[dest] - reserved[dest] - fee);
}
void verify_state(pconst@)
{
	require(flags.has("pinged") && flags["pinged"] == 1);
	require(flags.has("approved_call") && flags["approved_call"] == 1);
	require(flags.has("approved_transfer") && flags["approved_transfer"] == 1);
}
void set_transfer_amounts(pmut@, const real320&in first, const real320&in second)
{
	transfer_witness witness = transfer0.empty() ? transfer_witness() : transfer0.ref;
	witness.first = first;
	witness.second = second;
	transfer0 = witness;
}
void set_transfer_recipient(pmut@, uint index, const string&in dest)
{
	require(index < 2);
	transfer_witness witness = transfer0.empty() ? transfer_witness() : transfer0.ref;
	if (index == 0)
		witness.to0 = dest;
	else
		witness.to1 = dest;
	transfer0 = witness;
}
void report_state(pmut@)
{
	log::emit(transfer0.empty() ? transfer_witness() : transfer0.ref);
}
