varying<address> token_account;

void construct(pmut@, const address&in new_token_account)
{
	token_account = new_token_account;
}
real320 balance_of_test_token(pconst@)
{
	return token_account.ref.static_call<real320>("real320 balance_of(pconst@, const address&in)", tx::from());
}