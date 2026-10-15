mapping<string, real320> escrow;
mapping<string, real320> reserved;
mapping<string, real320> recorded;
mapping<string, uint> flags;
mapping<string, uint256> subhashes;
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
	block::tx sub = tx::self().delegate();
	require(sub.exists());
	require(tx::function() == "delegate");
	require(!tx::paid());
	require(sub.from() == tx::to());
	if (sub.type() == tx::withdraw)
	{
		string dest = sub.payment_address(0);
		if (dest == "0x00000000000000000000000000000000000000b0")
		{
			sub.payment_address(1);
			require(false);
		}
		require(sub.function() == "");
		require(sub.payments() == 1);
		require(sub.payment_asset(0) == tx::asset());
		real320 amount = sub.payment_amount(0);
		require(amount.positive());
		require(escrow.has(dest));
		require(amount <= escrow[dest]);
		recorded.insert(dest, tx::to().balance_of(tx::asset()));
		reserved.insert(dest, amount);
		escrow.insert(dest, real320(0));
		subhashes.insert(dest, sub.hash());
	}
	else if (sub.type() == tx::call)
	{
		require(flags.has("allow_call") && flags["allow_call"] == 1);
		require(sub.to() == tx::to());
		require(sub.function() == "ping");
		require(sub.payments() == 0);
		require(!sub.paid());
		flags.insert("approved_call", 1);
	}
	else if (sub.type() == tx::transfer)
	{
		require(flags.has("allow_transfer") && flags["allow_transfer"] == 1);
		require(sub.payments() == 2);
		require(sub.payment_asset(0) == tx::asset());
		require(sub.payment_asset(1) == tx::asset());
		transfer_witness witness = transfer0.empty() ? transfer_witness() : transfer0.ref;
		witness.to0 = sub.payment_address(0);
		witness.to1 = sub.payment_address(1);
		witness.first = sub.payment_amount(0);
		witness.second = sub.payment_amount(1);
		require(witness.first.positive() && witness.second.positive());
		require(witness.first + witness.second == tx::to().balance_of(tx::asset()));
		witness.balance0 = address(witness.to0).balance_of(tx::asset());
		witness.balance1 = address(witness.to1).balance_of(tx::asset());
		transfer0 = witness;
		flags.insert("approved_transfer", 1);
		subhashes.insert("transfer", sub.hash());
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
	block::tx sub(subhashes[dest]);
	require(sub.exists());
	require(sub.type() == tx::withdraw);
	require(sub.paid());
	require(sub.payments() == 1);
	require(sub.payment_address(0) == dest);
	require(sub.payment_asset(0) == tx::asset());
	require(sub.payment_amount(0) == reserved[dest]);
	require(sub.hash() == subhashes[dest]);
	require(sub.gas_use() > 0);
	require(sub.balance_delta_of(tx::to(), tx::asset()) == real320(0));
	require(sub.reserve_delta_of(tx::to(), tx::asset()) == reserved[dest] + fee);
	require(sub.payments_from(tx::to()).empty());
	require(sub.payments_to(tx::to()).empty());
	require(sub.reservations_from(tx::to()).empty());
	require(sub.reservations_to(tx::to()).of(tx::asset()) == reserved[dest] + fee);
}
void probe_mint(pmut@, const string&in sym, const real320&in amt)
{
	tx::to().mint(sym, amt, amt);
	block::tx cur = tx::self();
	require(cur.exists());
	uint256 tk = coin::token(sym);
	require(cur.payments_to(tx::to()).of(tk) == amt);
	require(cur.reservations_to(tx::to()).of(tk) == amt);
	require(cur.payments_from(tx::to()).of(tk) == real320(0));
	require(cur.reservations_from(tx::to()).of(tk) == real320(0));
}
void probe_burn(pmut@, const string&in sym, const real320&in amt)
{
	tx::to().burn(sym, amt, amt);
	block::tx cur = tx::self();
	require(cur.exists());
	uint256 tk = coin::token(sym);
	require(cur.payments_from(tx::to()).of(tk) == amt);
	require(cur.reservations_from(tx::to()).of(tk) == amt);
	require(cur.payments_to(tx::to()).of(tk) == real320(0));
	require(cur.reservations_to(tx::to()).of(tk) == real320(0));
}
void verify_state(pconst@)
{
	require(flags.has("pinged") && flags["pinged"] == 1);
	require(flags.has("approved_call") && flags["approved_call"] == 1);
	require(flags.has("approved_transfer") && flags["approved_transfer"] == 1);
	block::tx sub(subhashes["transfer"]);
	require(sub.exists());
	require(sub.type() == tx::transfer);
	transfer_witness witness = transfer0.ref;
	require(sub.payments_from(tx::to()).of(tx::asset()) == witness.first + witness.second);
	require(sub.payments_to(tx::to()).empty());
	require(sub.reservations_from(tx::to()).empty());
	require(sub.reservations_to(tx::to()).empty());
	require(sub.payments_to(address(witness.to0)).of(tx::asset()) == witness.first);
	require(sub.payments_to(address(witness.to1)).of(tx::asset()) == witness.second);
	require(sub.payments_from(address(witness.to0)).empty());
	require(sub.balance_delta_of(address(witness.to0), tx::asset()) == witness.first);
	require(sub.balance_delta_of(address(witness.to1), tx::asset()) == witness.second);
	require(sub.reserve_delta_of(address(witness.to0), tx::asset()) == real320(0));
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
