class token_storage
{
	address deployer;
	address contract;
	address account;
	string name;
	string symbol;
	real320 supply;
}

class token_transfer
{
	address from;
	address to;
	real320 value;
}

varying<token_storage> token;

void construct(pmut@, const string&in symbol, const string&in name, const address&in admin, const real320&in value)
{
	require(value.positive(), "illegal operation - supply must be positive");
	token_storage new_token;
	new_token.deployer = tx::from();
	new_token.contract = tx::to();
	new_token.account = admin;
	new_token.name = name;
	new_token.symbol = symbol;
	token = new_token;
    log::emit(new_token);
	mint(null, value);
}
void transfer(pmut@, const address&in to, const real320&in value)
{
	address from = tx::from();
	require(value.positive(), "illegal operation - value must be positive");
	require(value <= balance_of(null, from), string::from(from) + ": illegal operation - insufficient balance");
	from.burn(token.ref.symbol, value);
	to.mint(token.ref.symbol, value);

	token_transfer event;
	event.from = from;
	event.to = to;
	event.value = value;
	log::emit(event);
}
void mint(pmut@, const real320&in value)
{
	require(token.ref.account == tx::from(), "illegal operation - operation not permitted");
	require(value.positive(), "illegal operation - value must be positive");
	token_storage new_token = token.ref;
	new_token.supply += value;
	token = new_token;

	token_transfer event;
	event.from = address();
	event.to = token.ref.account;
	event.value = value;
	token.ref.account.mint(token.ref.symbol, value);
	log::emit(event);
}
void burn(pmut@, const real320&in value)
{
	require(value.positive(), "illegal operation - value must be positive");
	require(value <= token.ref.supply, "token supply will underflow (" + string::from(token.ref.supply) + " < " + string::from(value) + ")");
	token_storage new_token = token.ref;
	new_token.supply -= value;
	token = new_token;

	token_transfer event;
	event.from = tx::from();
	event.to = address();
	event.value = value;
	event.from.burn(token.ref.symbol, value);
	log::emit(event);
}
real320 balance_of(pconst@, const address&in account)
{
	return account.balance_of(coin::token(token.ref.symbol));
}
token_storage info(pconst@)
{
	return token.ref;
}