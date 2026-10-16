mapping<string, real320> bridge_fees;
mapping<string, real320> escrow;
mapping<string, real320> reserved;
mapping<string, real320> recorded;
mapping<string, uint256> routes;
mapping<string, uint> flags;

void construct(pmut@)
{
}
void arm_withdraw(pmut@, const string&in dest, const uint256&in hash, const real320&in fee)
{
	escrow.insert(dest, tx::to().balance_of(tx::asset()));
	routes.insert(dest, hash);
	bridge_fees.insert(dest, fee);
	flags.insert("armed", 1);
}
void delegate(pmut@, const string&in dest, const real320&in amount)
{
	require(flags.has("armed") && flags["armed"] == 1);
	require(escrow.has(dest) && routes.has(dest));
	require(amount.positive());
	require(amount <= escrow[dest]);
	require(bridge::requires_send(), "withdrawal feature flag is not set");
	recorded.insert(dest, tx::to().balance_of(tx::asset()));
	reserved.insert(dest, amount);
	escrow.insert(dest, real320(0));
	flags.insert("armed", 0);
	bridge::send(routes[dest], tx::asset(), dest, amount, bridge_fees[dest]);
}
void try_send(pmut@, const uint256&in hash)
{
	bridge::send(hash, tx::asset(), "0x89a0181659bd280836A2d33F57e3B5Dfa1a823CE", real320(1), real320("0.000001"));
}
void try_link(pmut@, const uint256&in hash)
{
	bridge::link(hash, tx::asset(), "routetest");
}
void verify_withdraw(pmut@, const string&in dest, const real320&in fee)
{
	require(escrow.has(dest));
	require(escrow[dest] == real320(0));
	require(recorded.has(dest) && reserved.has(dest));
	require(tx::to().balance_of(tx::asset()) == recorded[dest] - reserved[dest] - fee);
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