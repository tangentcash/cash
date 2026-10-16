class probe_pod
{
    uint256 a = 0;
    string b = "";
    array<uint256> c;
}

void trap_loop(pmut@)
{
    while (true)
    {
    }
}
void trap_recursion(pmut@)
{
    trap_recursion(null);
}
void trap_alloc(pmut@)
{
    array<uint256> huge(8388608);
    log::emit(probe_pod());
}
void trap_string_growth(pmut@)
{
    string buffer = "x";
    while (buffer.size() < 67108864)
    {
        buffer += buffer;
    }
}
void trap_array_oob(pmut@)
{
    array<uint256> values(1);
    while (values.size() < 1048576)
    {
        array<uint256> copy = values;
        values = copy;
    }
    values.at(9999999) = 1;
}
void trap_substring_oob(pconst@)
{
    string text = "abc";
    uint8 leaked = text.at(3 + uint(block::priority()));
    log::emit(probe_pod());
}
void trap_log_oob(pmut@)
{
    log::emit(probe_pod());
    probe_pod leaked = log::get<probe_pod>(999);
}
void trap_call_missing(pmut@)
{
    address self = tx::to();
    self.call<void>("void does_not_exist()", payable());
}
void trap_call_malformed(pconst@)
{
    address self = tx::to();
    self.call<void>("void trap_loop()", payable(), 1);
}
void trap_log_type_mismatch(pmut@)
{
    log::emit(probe_pod());
    array<uint256> mismatched = log::get<array<uint256>>(0);
}
void trap_call_recursion_a(pmut@)
{
    address self = tx::to();
    self.call<void>("void trap_call_recursion_b()", payable());
}
void trap_call_recursion_b(pmut@)
{
    address self = tx::to();
    self.call<void>("void trap_call_recursion_a()", payable());
}