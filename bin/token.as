class token_info
{
	address owner;
	string name;
	string symbol;
	uint8 decimals = 0;
	uint256 supply = 0;
}

class token_balance
{
	address owner;
	uint256 value = 0;
}

class token_transfer
{
	address from;
	address to;
	uint256 value = 0;
}

token_info initialize(program@ context, const address&in owner, const uint256&in value)
{
	token_info token;
	token.owner = owner;
	token.name = "USD Token";
	token.symbol = "USD";
	token.decimals = 2;
	token.supply = value;

	token_balance output;
	output.owner = token.owner;
	output.value = value;

	context.store(context.to(), token);
	context.store(output.owner, output);
	return token;
}
token_transfer transfer(program@ context, const address&in to, const uint256&in value)
{
	token_balance input;
	input.owner = context.from();
	context.load(input.owner, input);

	token_balance output;
	output.owner = to;
	context.load(output.owner, output);

	uint256 from_delta = input.value - value;
	if (from_delta > input.value)
		throw exception_ptr("logical_error", "from balance will underflow (" + input.value.to_string() + " < " + value.to_string() + ")");

	uint256 to_delta = output.value + value;
	if (to_delta < output.value)
		throw exception_ptr("argument_error", "to balance will overflow (" + output.value.to_string() + " + " + value.to_string() + " > uint256_max)");

	input.value = from_delta;
	output.value = to_delta;
	context.store(input.owner, input);
	context.store(output.owner, output);

	token_transfer event;
	event.from = input.owner;
	event.to = output.owner;
	event.value = value;
	return event;
}
token_balance mint(program@ context, const uint256&in value)
{
	token_info token;
	if (!context.load(context.to(), token) || token.owner != context.from())
		throw exception_ptr("logical_error", "from does not own the token");

	token_balance output;
	output.owner = token.owner;
	context.load(output.owner, output);

	uint256 supply_delta = token.supply + value;
	if (supply_delta < token.supply)
		throw exception_ptr("argument_error", "token supply will overflow (" + output.value.to_string() + " + " + value.to_string() + " > uint256_max)");

	uint256 to_delta = output.value + value;
	if (to_delta < output.value)
		throw exception_ptr("argument_error", "owner balance will overflow (" + output.value.to_string() + " + " + value.to_string() + " > uint256_max)");

	token.supply = supply_delta;
	output.value = to_delta;
	context.store(context.to(), token);
	context.store(output.owner, output);
	return output;
}
token_balance burn(program@ context, const uint256&in value)
{
	token_info token;
	if (!context.load(context.to(), token) || token.owner != context.from())
		throw exception_ptr("logical_error", "from does not own the token");

	token_balance output;
	output.owner = token.owner;
	context.load(output.owner, output);

	uint256 supply_delta = token.supply - value;
	if (supply_delta > token.supply)
		throw exception_ptr("logical_error", "token supply will underflow (" + token.supply.to_string() + " < " + value.to_string() + ")");

	uint256 to_delta = output.value - value;
	if (to_delta > output.value)
		throw exception_ptr("argument_error", "owner balance will underflow (" + output.value.to_string() + " < " + value.to_string() + ")");

	token.supply = supply_delta;
	output.value = to_delta;
	context.store(context.to(), token);
	context.store(output.owner, output);
	return output;
}
token_balance balance(const program@ context, const address&in owner)
{
	token_balance output;
	output.owner = context.from();
	context.load(output.owner, output);
	return output;
}
token_info info(const program@ context)
{
	token_info token;
	context.load(context.to(), token);
	return token;
}