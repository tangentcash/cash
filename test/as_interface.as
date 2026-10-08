namespace test
{
    class pod
    {
        uint32 a;
        uint32 b;

        pod() { a = b = 0; }
        pod(uint32 new_a, uint32 new_b) { a = new_a; b = new_b; }
        bool opEquals(const pod&in other) const { return a == other.a && b == other.b; }
    }

    varying<pod> varying0;
    mapping<string, pod> mapping0;
    ranging<string, uint256, pod> ranging0;

    void module_array()
    {
        array<pod> numbers;
        array<pod> numbers_reversed;
        array<pod> numbers_sized = array<pod>(32);
        array<pod> numbers_sized_default = array<pod>(32, pod(32, 64));
        require(numbers.empty() && numbers.size() == 0);
        require(numbers_reversed.empty() && numbers_reversed.size() == 0);
        require(!numbers_sized.empty() && numbers_sized.size() == 32);
        require(!numbers_sized_default.empty() && numbers_sized_default.size() == 32);
        for (usize i = 0; i < numbers_sized.size(); i++)
        {
            numbers.push(pod(i, i * 2));
            numbers_reversed.push_front(pod(i, i * 2));
            numbers_sized[i] = pod(i, i * 2);
        }

        array<pod> numbers_copy = numbers, numbers_reversed_copy = numbers;
        require(!numbers_copy.empty() && numbers_copy.size() == numbers.size() && !numbers.empty() && numbers.size() == 32);
        require(!numbers_reversed_copy.empty() && numbers_reversed_copy.size() == numbers_reversed.size() && !numbers_reversed.empty() && numbers_reversed.size() == 32);
        numbers_reversed_copy.reverse();
        for (usize i = 0; i < numbers.size(); i++)
        {
            usize i_reversed = (numbers_reversed.size() - 1) - i;
            require(numbers[i].a == i && numbers[i].b == i * 2);
            require(numbers_reversed[i].a == i_reversed && numbers_reversed[i].b == i_reversed * 2);
            require(numbers_reversed_copy[i].a == i_reversed && numbers_reversed_copy[i].b == i_reversed * 2);
            require(numbers_sized[i].a == i && numbers_sized[i].b == i * 2);
            require(numbers_sized_default[i].a == 32 && numbers_sized_default[i].b == 64);
            require(numbers_copy[i].a == i && numbers_copy[i].b == i * 2);
        }

        require(numbers.front().a == 0);
        require(numbers.back().a == 31);
        numbers.resize(0);
        numbers_reversed.clear();
        numbers_sized.pop();
        numbers_sized.pop_front();
        require(numbers.size() == 0 && numbers.empty());
        require(numbers_reversed.size() == 0 && numbers_reversed.empty());
        require(numbers_sized.size() == 30 && !numbers_sized.empty());
        require(numbers_sized.front().a == 1);
        require(numbers_sized.back().a == 30);
        numbers_sized.insert(5, pod(100, 100));
        require(numbers_sized.size() == 31 && numbers_sized[5].a == 100);
        numbers_sized.insert(29, numbers_copy);
        require(numbers_sized.size() == 63 && numbers_sized[29].a == 0);
        numbers_sized.erase(1);
        require(numbers_sized.size() == 62 && numbers_sized[1].a == 3);
        numbers_sized.erase(29, 32);
        require(numbers_sized.size() == 30 && numbers_sized[29].a == 30);
        numbers_sized.swap(0, 29);
        require(numbers_sized.front().a == 30);
        require(numbers_sized.back().a == 1);
    }
    void module_string()
    {
        string a = "hello";
        string b = a;
        string c;
        require(a == b && b != c);
        require(a.front() == 'h' && a.back() == 'o');
        require(a[1] == 'e' && a[3] == 108 && a.at(0) == 'h' && !a.empty() && a.size() == 5);
        a += b;
        a += a;
        a += 32;
        a = ' ' + a;
        a = a + 32;
        b = c;
        require(a != b && b == c && a == " hellohellohellohello  " && b.empty() && c.empty());
        b = a;
        b.trim();
        a.trim_front();
        require(a == "hellohellohellohello  " && b == "hellohellohellohello");
        a.trim_back();
        require(a == "hellohellohellohello");
        a.clear();
        require(a.empty() && a.size() == 0);
        a.append("abcd");
        a.append('e');
        a.push('f');
        require(!a.empty() && a.size() == 6 && a == "abcdef");
        a.pop();
        require(a.size() == 5 && a == "abcde");
        require(a.starts_with("ab") && a.starts_with("bc", 1) && a.ends_with("de"));
        b = a.substring(1);
        c = b.substring(2, 2);
        require(b == "bcde" && c == "de");
        a = "ABCDEF01234";
        a.lower();
        require(a == "abcdef01234");
        a.upper();
        require(a == "ABCDEF01234");
        a.reverse();
        require(a == "43210FEDCBA");
        a += "BDBDBD";
        require(a == "43210FEDCBABDBDBD");
        require(a.rfind("BD") == 15 && a.rfind('D') == 16 && a.rfind("0", 4) == 4 && a.rfind('0', 4) == 4 && a.rfind("9") == string::npos && a.rfind('9') == string::npos);
        require(a.find("BD") == 11 && a.find('D') == 7 && a.find("0", 4) == 4 && a.find('0', 4) == 4 && a.find("9") == string::npos && a.find('9') == string::npos);
        require(a.find_first_of("1234") == 0 && a.find_first_of("1234", 1) == 1);
        require(a.find_first_not_of("123") == 0 && a.find_first_not_of("123", 1) == 4);
        require(a.find_last_of("BD") == 16 && a.find_last_of("BD", 14) == 14);
        require(a.find_last_not_of("BD") == 10 && a.find_last_not_of("BD", 14) == 10);
        c = "a b c d e f";
        array<string>@ cs = c.split(" ");
        require(cs.size() == 6);
        require(cs[0] == "a" && cs[1] == "b" && cs[2] == "c" && cs[3] == "d" && cs[4] == "e" && cs[5] == "f");
        a = "123";
        b = "5f";
        require(a.i8() == 123 && a.i16() == 123 && a.i32() == 123 && a.i64() == 123 && a.u8() == 123 && a.u16() == 123 && a.u32() == 123 && a.u64() == 123 && a.u128() == 123 && a.u256() == 123 && a.r320() == 123);
        require(b.i8(16) == 95 && b.i16(16) == 95 && b.i32(16) == 95 && b.i64(16) == 95 && b.u8(16) == 95 && b.u16(16) == 95 && b.u32(16) == 95 && b.u64(16) == 95 && b.u128(16) == 95 && b.u256(16) == 95 && b.r320(16) == 95);
        require(c.i8() == 0 && c.i16() == 0 && c.i32() == 0 && c.i64() == 0 && c.u8() == 0 && c.u16() == 0 && c.u32() == 0 && c.u64() == 0 && c.u128() == 0 && c.u256() == 0 && c.r320().nan());
        require(string::from(int8(10)) == "10" && string::from(int16(10)) == "10" && string::from(int32(10)) == "10" && string::from(int64(10)) == "10");
        require(string::from(uint8(10)) == "10" && string::from(uint16(10)) == "10" && string::from(uint32(10)) == "10" && string::from(uint64(10)) == "10" && string::from(uint128(10)) == "10" && string::from(uint256(10)) == "10" && string::from(real320(10)) == "10");
        require(string::from(address("tcrt1xjlfu08tgc5jttkztcl39ml5433jssmnvdlqtn0")) == "tcrt1xjlfu08tgc5jttkztcl39ml5433jssmnvdlqtn0");
    }
    void module_uint128()
    {
        uint128 a, b = 10, c = 0x10, d = 0x4e03657aea45a94fc7d47ba826c8d667, e = "100";
        require(!a && b && a == 0 && b == 10 && c == 0x10 && d == 0x4e03657aea45a94fc7d47ba826c8d667 && e == 100);
        require(b.i8() == 10 && b.i16() == 10 && b.i32() == 10 && b.i64() == 10 && b.u8() == 10 && b.u16() == 10 && b.u32() == 10 && b.u64() == 10 && b.u256() == 10 && b.r320() == 10);
        require(b.bits() == 4 && b.bytes() == 1);

        uint128 f = 10;
        uint128 x = f;
        f = f * f + f / f;
        ++f;
        f++;
        f += 3;
        f -= 1;
        f *= 4;
        f /= 2;
        f = f % 202;
        f *= f % 3;
        --f;
        f--;
        require(f == 14 && f > 0 && f < 32 && f >= 14 && f <= 14 && x == 10);

        f /= 0;
        require(f == 0);
    }
    void module_uint256()
    {
        uint256 a, b = 10, c = 0x10, d = 0x4e03657aea45a94fc4e03657aea45a94fc7d47ba826c8d6677d47ba826c8d667, e = "100";
        require(!a && b && a == 0 && b == 10 && c == 0x10 && d == 0x4e03657aea45a94fc4e03657aea45a94fc7d47ba826c8d6677d47ba826c8d667 && e == 100);
        require(b.i8() == 10 && b.i16() == 10 && b.i32() == 10 && b.i64() == 10 && b.u8() == 10 && b.u16() == 10 && b.u32() == 10 && b.u64() == 10 && b.u128() == 10 && b.r320() == 10);
        require(b.bits() == 4 && b.bytes() == 1);

        uint128 y = 0x4e03657aea45a94fc7d47ba826c8d667;
        y *= 2;

        uint256 y_copy = y;
        require(y_copy == 207394837647017091719440718868182576334);

        uint256 f = 10;
        uint256 x = f;
        f = f * f + f / f;
        ++f;
        f++;
        f += 3;
        f -= 1;
        f *= 4;
        f /= 2;
        f = f % 202;
        f *= f % 3;
        --f;
        f--;
        require(f == 14 && f > 0 && f < 32 && f >= 14 && f <= 14 && x == 10);

        f /= 0;
        require(f == 0);
    }
    void module_real320()
    {
        real320 w, a = false, b = 4, c = 0x4, d = 0x4e03657aea45a94fc7d47ba826c8d667, e = 0x4e03657aea45a94fc4e03657aea45a94fc7d47ba826c8d6677d47ba826c8d667;
        require(w == 0 && !a && a == 0 && b == 4 && c == 0x4 && d == 0x4e03657aea45a94fc7d47ba826c8d667 && e == 0x4e03657aea45a94fc4e03657aea45a94fc7d47ba826c8d6677d47ba826c8d667);
        require(b.i8() == 4 && b.i16() == 4 && b.i32() == 4 && b.i64() == 4 && b.u8() == 4 && b.u16() == 4 && b.u32() == 4 && b.u64() == 4 && b.u128() == 4 && b.u256() == 4);

        real320 ff = uint256(0x4e03657aea45a94fc7d47ba826c8d667), x = "123";
        real320 ff1 = real320::from("4e03657aea45a94fc7d47ba826c8d667", 16);
        real320 ff2 = real320::from("32.32", 10);
        require(ff == 0x4e03657aea45a94fc7d47ba826c8d667 && ff == ff1 && ff2 == 32.32 && x == 123);
        
        real320 y = 564582449933685855403723054226767221243417946799163586602776791268239461934704.352864031208553659;
        require(y == 564582449933685855403723054226767221243417946799163586602776791268239461934704.352864031208553659);
        require(-y == -real320(564582449933685855403723054226767221243417946799163586602776791268239461934704.352864031208553659));
        require(y && !y.nan() && !y.zero() && !y.zero_or_nan() && y.positive() && !y.negative());

        real320 f = 10;
        real320 x1 = f;
        f = f * f + f / f;
        ++f;
        f++;
        f += 3;
        f -= 1;
        f *= 4;
        f /= 2;
        --f;
        f--;
        require(f == 208 && f > 0 && f < 256 && f >= 208 && f <= 208 && x1 == 10);

        f /= 0;
        require(f.nan());

        real320 z = real320::enan();
        require(!z && z.nan() && !z.zero() && z.zero_or_nan() && !z.positive() && !z.negative());
    }
    void module_payable()
    {
        payable pays;
        pays.plus(1, 10);
        pays.plus(2, 20);
        pays.plus(3, 40);
        pays.minus(3, 10);
        require(!pays.empty() && pays.size() == 3 && pays.has(1) && pays.has(2) && pays.has(3) && !pays.has(4));
        require(pays[0] == 1 && pays[1] == 2 && pays[2] == 3);
        require(pays.of(1) == 10 && pays.of(2) == 20 && pays.of(3) == 30 && pays.total() == 60);
        pays.minus(30);
        require(!pays.has(1) && !pays.has(2) && pays.has(3) && pays.of(3) == 30 && pays.total() == 30);

        payable pays_copy = pays;
        require(!pays_copy.has(1) && !pays_copy.has(2) && pays_copy.has(3) && pays_copy.of(3) == 30 && pays_copy.total() == 30);
    }
    void module_address()
    {
        uint256 base = uint256(0x97d3c79d68c524b5d84bc7e25dfe958c65086e6c000000000000000000000000);
        address a = base;
        address b = "tcrt1xjlfu08tgc5jttkztcl39ml5433jssmnvdlqtn0";
        address c = b;
        address d;
        require(a == b && b == c && c.u256() == base && !a.empty() && d.empty());
        
        address contract = tx::to();
        uint256 asset = coin::token("TOKEN");
        contract.mint("TOKEN", 123 + 321, 321);
        require(contract.token_balance_of("TOKEN") == 123 && contract.token_reserve_of("TOKEN") == 321 && contract.balance_of(asset) == 123 && contract.reserve_of(asset) == 321);
        contract.burn("TOKEN", 321, 321);
        require(contract.token_balance_of("TOKEN") == 123 && contract.token_reserve_of("TOKEN") == 0 && contract.balance_of(asset) == 123 && contract.reserve_of(asset) == 0);
        a.pay(asset, 10);
        require(a.token_balance_of("TOKEN") == 10 && a.balance_of(asset) == 10 && contract.token_balance_of("TOKEN") == 113 && contract.balance_of(asset) == 113);

        payable target;
        target.plus(asset, 13);
        a.pay(target);
        require(a.token_balance_of("TOKEN") == 23 && a.balance_of(asset) == 23 && contract.token_balance_of("TOKEN") == 100 && contract.balance_of(asset) == 100);
        a.burn("TOKEN", 23);
        contract.burn("TOKEN", 100);
        require(a.token_balance_of("TOKEN") == 0 && a.balance_of(asset) == 0 && contract.token_balance_of("TOKEN") == 0 && contract.balance_of(asset) == 0);

        string function = "array<string> test_string_split(pmut@, const string&in)";
        require(contract.callable(function));

        array<string> values = contract.call<array<string>>(function, payable(), "1 2 3 4 5 6");
        require(values.size() == 6 && values[0] == "1" && values[1] == "2" && values[2] == "3" && values[3] == "4" && values[4] == "5" && values[5] == "6");
        require(contract.token_balance_of("TSS_NFT") == 1);
        contract.burn("TSS_NFT", 1, 0);
        require(contract.token_balance_of("TSS_NFT") == 0);
    }
    void module_abi()
    {
        abi wbuffer;
        wbuffer.wu8(true);
        wbuffer.wu160(address("tcrt1xjlfu08tgc5jttkztcl39ml5433jssmnvdlqtn0"));
        wbuffer.wu256(1234567890);
        wbuffer.wr320(10.99);
        wbuffer.wstr("Hello, World!");
        
        string data = wbuffer.data();
        abi rbuffer = data, rbuffer_copy = wbuffer;
        rbuffer.merge(rbuffer_copy.data());
        rbuffer.seek(0);
        for (usize i = 0; i < 2; i++)
        {
            bool u8; address u160; uint256 u256; real320 r320; string str;
            require(rbuffer.ru8(u8) && u8 == true);
            require(rbuffer.ru160(u160) && u160 == address("tcrt1xjlfu08tgc5jttkztcl39ml5433jssmnvdlqtn0"));
            require(rbuffer.ru256(u256) && u256 == 1234567890);
            require(rbuffer.rr320(r320) && r320 == 10.99);
            require(rbuffer.rstr(str) && str == "Hello, World!");
        }
        rbuffer.clear();
        require(rbuffer.data().empty());
    }
    void module_varying()
    {
        require(varying0.empty());
        varying0 = pod(30, 15);
        require(!varying0.empty() && varying0.ref.a == 30 && varying0.ref.b == 15);
        varying0.set(pod(15, 30));
        require(!varying0.empty() && varying0.ref.a == 15 && varying0.ref.b == 30);
        varying0.set_if(true, pod(1, 2));
        require(!varying0.empty() && varying0.ref.a == 1 && varying0.ref.b == 2);
        varying0.set_if(false, pod(3, 4));
        require(varying0.empty());
        varying0.set(pod(15, 30));
        require(!varying0.empty() && varying0.ref.a == 15 && varying0.ref.b == 30);
        varying0.erase();
        require(varying0.empty());
    }
    void module_mapping()
    {
        mapping0.insert("inserted", pod(1, 2));
        mapping0.insert_if(true, "inserted_if_true", pod(3, 4));
        mapping0.insert_if(false, "not_inserted", pod(5, 6));
        require(mapping0.has("inserted") && mapping0.has("inserted_if_true") && !mapping0.has("not_inserted"));
        pod a = mapping0["inserted"], b = mapping0["inserted_if_true"];
        require(a.a == 1 && a.b == 2 && b.a == 3 && b.b == 4);
        mapping0.erase("inserted");
        mapping0.erase("inserted_if_true");
        require(!mapping0.has("inserted") && !mapping0.has("inserted_if_true"));
    }
    void module_ranging()
    {
        ranging0.insert("a", 1, pod(1, 2));
        ranging0.insert("b", 1, pod(2, 3), 10);
        ranging0.insert_if(true, "c", 1, pod(4, 5), 100);
        ranging0.insert_if(false, "d", 1, pod(6, 7));
        ranging0.insert("a", 2, pod(6, 7));
        ranging0.insert("b", 2, pod(8, 9), 4);
        ranging0.insert("c", 2, pod(10, 11));
        ranging0.insert("d", 2, pod(12, 13));
        require(ranging0.has("a", 1) && ranging0.has("b", 1) && ranging0.has("c", 1) && !ranging0.has("d", 1));
        require(ranging0.has("a", 2) && ranging0.has("b", 2) && ranging0.has("c", 2) && ranging0.has("d", 2));
        require(ranging0.has_x("a") && ranging0.has_x("b") && ranging0.has_x("c") && ranging0.has_x("d"));
        require(ranging0.has_y(1) && ranging0.has_y(2));
        pod a1 = ranging0["a", 1], b1 = ranging0["b", 1], c1 = ranging0["c", 1];
        pod a2 = ranging0["a", 2], b2 = ranging0["b", 2], c2 = ranging0["c", 2], d2 = ranging0["d", 2];
        require(a1.a == 1 && a1.b == 2 && b1.a == 2 && b1.b == 3 && c1.a == 4 && c1.b == 5);
        require(a2.a == 6 && a2.b == 7 && b2.a == 8 && b2.b == 9 && c2.a == 10 && c2.b == 11 && d2.a == 12 && d2.b == 13);
        ranging0.erase("d", 2);
        require(!ranging0.has("d", 2));
        ranging_slice slice1 = ranging0.x("b").gt(0).desc().offset(0).count(2);
        ranging_slice slice2 = ranging0.x("b").gt(0).asc();
        ranging_slice slice3 = ranging0.y(1).gte(0).asc();
        ranging_slice slice4 = ranging0.y(2).lt(4).asc();

        pod v1, v2, v3, v4;
        uint256 b2_y, b1_y, b1_r;
        require(slice1.next(v1) && v1 == b1);
        require(slice1.next(v2) && v2 == b2);
        require(!slice1.next(v2));
        require(slice2.next(v3, b2_y) && v3 == b2 && b2_y == 2);
        require(slice2.next(v4, b1_y, b1_r) && v4 == b1 && b1_y == 1 && b1_r == 10);
        require(!slice2.next(v4));
        require(slice3.next(v1) && v1 == a1);
        require(slice3.next(v2) && v2 == b1);
        require(slice3.next(v3) && v3 == c1);
        require(!slice3.next(v3));
        require(slice4.next(v1) && v1 == a2);
        require(slice4.next(v2) && v2 == c2);
        require(!slice4.next(v3));
        ranging0.erase("a", 1);
        ranging0.erase("b", 1);
        ranging0.erase("c", 1);
        ranging0.erase("a", 2);
        ranging0.erase("b", 2);
        ranging0.erase("c", 2);
        require(!ranging0.has("a", 1) && !ranging0.has("b", 1) && !ranging0.has("c", 1) && !ranging0.has("d", 1));
        require(!ranging0.has("a", 2) && !ranging0.has("b", 2) && !ranging0.has("c", 2) && !ranging0.has("d", 2));
    }
    void module_log()
    {
        log::emit(pod(1, 2));
        log::emit(pod(3, 4));
        log::emit(int(128));
        log::event(int(256), pod(5, 6));

        pod a = log::get<test::pod>(0);
        pod b = log::get<test::pod>(1);
        int c = log::get<int>(0);
        pod d = log::get_event<test::pod>(int(11), 1);
        require(a.a == 1 && a.b == 2 && b.a == 3 && b.b == 4 && c == 128 && d.a == 5 && d.b == 6);
        require(log::into(0, a));
        require(log::into(1, b));
        require(log::into(0, c));
        require(log::event_into(int(33), 1, d));
        require(a.a == 1 && a.b == 2 && b.a == 3 && b.b == 4 && c == 128 && d.a == 5 && d.b == 6);
    }
    void module_block()
    {
        require(!block::proposer().empty());
        require(block::parent_hash() > 0);
        require(block::gas_limit() > 0);
        require(block::gas_use() > 0 && block::gas_use() < block::gas_limit());
        require(block::gas_left() > 0 && block::gas_left() < block::gas_limit());
        require(block::difficulty() > 0);
        require(block::time() > 0);
        require(block::time_between(1, 201) == 200);
        require(block::priority() == 0);
        require(block::number() > 0);
    }
    void module_tx()
    {
        require(!tx::paid());
        require(!tx::from().empty() && !tx::to().empty());
        require(tx::value().total() == 0);
        require(tx::blockchain() == "TAN");
        require(tx::token().empty());
        require(tx::contract().empty());
        require(tx::gas_price().zero());
        require(tx::gas_limit() > 0);
        require(tx::gas_use() > 0 && tx::gas_use() < tx::gas_limit());
        require(tx::gas_left() > 0 && tx::gas_left() < tx::gas_limit());
        require(tx::asset() == coin::native());
    }
    void module_coin()
    {
        uint256 token = coin::token("TOKEN");
        require(coin::native() == 0);
        require(coin::blockchain_of(token) == "TAN" && coin::token_of(token) == "TOKEN");
        require(coin::contract_of(token) == coin::contract_of(coin::id_of("TAN", "TOKEN", string::from(tx::to()))));

        string name = coin::name_of(token);
        require(name.find(coin::blockchain_of(token)) != string::npos && name.find(coin::token_of(token)) != string::npos && name.find(coin::contract_of(token)) != string::npos);
    }
    void module_alg()
    {
        real320 r_v320 = 10.994;
        uint256 r_v256 = alg::to_r256(r_v320);
        require(r_v256 == 10994000000000000000);
        require(alg::from_r256(r_v256) == r_v320);

        string b256 = alg::from_u256(r_v256);
        require(b256.size() == 32 && alg::to_u256(b256) == r_v256);

        uint256 message_hash = 0xadad1970fc78cc05c00a4f735068f55bc0c20405b006756409c8e7cf825c42c6;
        string message_signature = alg::from_e16(0x3cc6407198c7e7c82f501ca39eea20d0a71d0c30d08017dbc30277a0675604987ee71138759ad7a041d5449ea718c36d03c4b013f2f223a43322d543fb68812201);
        require(alg::erecover160(message_hash, message_signature) == address("tcrt1xu0k7jd2hsv2x5h80tcslpk3n0kvzzw5kup6vng"));
        require(alg::to_e16(alg::erecover264(message_hash, message_signature)) == 0x03a236872d46a5fb9b4810dd1b84c1b763b00ab00f7976add2f9007f7ba636d4ff);
        require(alg::prandom256() != alg::prandom256());
        require(alg::to_e16(alg::crc32("abc")) == "0x363e99a9");
        require(alg::to_e16(alg::ripemd160("abc")) == 0x8eb208f7e05d987a9b044a8e98c6b087f15a0bfc);
        require(alg::blake2b256("abc") == uint256(0xbddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319));
        require(alg::to_e16(alg::blake2b256s("abc")) == 0xbddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319);
        require(alg::keccak256("abc") == uint256(0xba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad));
        require(alg::keccak256("abc") == uint256(0xba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad));
        require(alg::to_e16(alg::keccak256s("abc")) == 0xba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad);
        require(alg::to_e16(alg::keccak512("abc")) == 0x18587dc2ea106b9a1563e32b3312421ca164c7f1f07bc922a9c83d77cea3a1e5d0c69910739025372dc14ac9642629379540c17e2a65b19d77aa511a9d00bb96);
        require(alg::sha256("abc") == uint256(0x4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45));
        require(alg::to_e16(alg::sha256s("abc")) == 0x4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45);
        require(alg::to_e16(alg::sha512("abc")) == 0xb751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0);
    }
    void module_math()
    {
        require(math::min_value<uint8>() == 0);
        require(math::min_value<int8>() == -128);
        require(math::min_value<uint16>() == 0);
        require(math::min_value<int16>() == -32768);
        require(math::min_value<uint32>() == 0);
        require(math::min_value<int32>() == -2147483648);
        require(math::min_value<uint64>() == 0);
        require(math::min_value<int64>() == -9223372036854775808);
        require(math::min_value<uint128>() == 0);
        require(math::min_value<uint256>() == 0);
        require(math::min_value<real320>() == -real320(999999999999999999999999999999999999999999999999999999999999999999999999999999.999999999999999999));
        require(math::max_value<uint8>() == 255);
        require(math::max_value<int8>() == 127);
        require(math::max_value<uint16>() == 65535);
        require(math::max_value<int16>() == 32767);
        require(math::max_value<uint32>() == 4294967295);
        require(math::max_value<int32>() == 2147483647);
        require(math::max_value<uint64>() == 18446744073709551615);
        require(math::max_value<int64>() == 9223372036854775807);
        require(math::max_value<uint128>() == 340282366920938463463374607431768211455);
        require(math::max_value<uint256>() == 115792089237316195423570985008687907853269984665640564039457584007913129639935);
        require(math::max_value<real320>() == 999999999999999999999999999999999999999999999999999999999999999999999999999999.999999999999999999);
        require(math::abs<int8>(-44) == 44 && math::abs<int8>(45) == 45 && math::abs<uint8>(100) == 100);
        require(math::abs<int16>(-44) == 44 && math::abs<int16>(45) == 45 && math::abs<uint16>(100) == 100);
        require(math::abs<int32>(-44) == 44 && math::abs<int32>(45) == 45 && math::abs<uint32>(100) == 100);
        require(math::abs<int64>(-44) == 44 && math::abs<int64>(45) == 45 && math::abs<uint64>(100) == 100);
        require(math::abs<uint128>(100) == 100 && math::abs<uint256>(100) == 100 && math::abs<real320>(-44) == 44 && math::abs<real320>(45) == 45);
        require(math::min<int8>(-8, 16) == -8 && math::min<uint8>(8, 16) == 8);
        require(math::min<int16>(-8, 16) == -8 && math::min<uint16>(8, 16) == 8);
        require(math::min<int32>(-8, 16) == -8 && math::min<uint32>(8, 16) == 8);
        require(math::min<int64>(-8, 16) == -8 && math::min<uint64>(8, 16) == 8);
        require(math::min<uint128>(8, 16) == 8 && math::min<uint256>(8, 16) == 8 && math::min<real320>(8, 16) == 8);
        require(math::max<int8>(-8, 16) == 16 && math::max<uint8>(8, 16) == 16);
        require(math::max<int16>(-8, 16) == 16 && math::max<uint16>(8, 16) == 16);
        require(math::max<int32>(-8, 16) == 16 && math::max<uint32>(8, 16) == 16);
        require(math::max<int64>(-8, 16) == 16 && math::max<uint64>(8, 16) == 16);
        require(math::max<uint128>(8, 16) == 16 && math::max<uint256>(8, 16) == 16 && math::max<real320>(8, 16) == 16);
        require(math::clamp<int8>(-5, -8, 16) == -5 && math::clamp<int8>(-10, -8, 16) == -8 && math::clamp<int8>(20, -8, 16) == 16);
        require(math::clamp<int16>(-5, -8, 16) == -5 && math::clamp<int16>(-10, -8, 16) == -8 && math::clamp<int16>(20, -8, 16) == 16);
        require(math::clamp<int32>(-5, -8, 16) == -5 && math::clamp<int32>(-10, -8, 16) == -8 && math::clamp<int32>(20, -8, 16) == 16);
        require(math::clamp<int64>(-5, -8, 16) == -5 && math::clamp<int64>(-10, -8, 16) == -8 && math::clamp<int64>(20, -8, 16) == 16);
        require(math::clamp<real320>(-5, -8, 16) == -5 && math::clamp<real320>(-10, -8, 16) == -8 && math::clamp<real320>(20, -8, 16) == 16);
        require(math::clamp<uint8>(10, 8, 16) == 10 && math::clamp<uint8>(5, 8, 16) == 8 && math::clamp<uint8>(20, 8, 16) == 16);
        require(math::clamp<uint16>(10, 8, 16) == 10 && math::clamp<uint16>(5, 8, 16) == 8 && math::clamp<uint16>(20, 8, 16) == 16);
        require(math::clamp<uint32>(10, 8, 16) == 10 && math::clamp<uint32>(5, 8, 16) == 8 && math::clamp<uint32>(20, 8, 16) == 16);
        require(math::clamp<uint64>(10, 8, 16) == 10 && math::clamp<uint64>(5, 8, 16) == 8 && math::clamp<uint64>(20, 8, 16) == 16);
        require(math::clamp<uint128>(10, 8, 16) == 10 && math::clamp<uint128>(5, 8, 16) == 8 && math::clamp<uint128>(20, 8, 16) == 16);
        require(math::clamp<uint256>(10, 8, 16) == 10 && math::clamp<uint256>(5, 8, 16) == 8 && math::clamp<uint256>(20, 8, 16) == 16); 
        require(math::lerp<int8>(2, 10, 5) == 42 && math::lerp<uint8>(2, 10, 5) == 42);
        require(math::lerp<int16>(2, 10, 5) == 42 && math::lerp<uint16>(2, 10, 5) == 42);
        require(math::lerp<int32>(2, 10, 5) == 42 && math::lerp<uint32>(2, 10, 5) == 42);
        require(math::lerp<int64>(2, 10, 5) == 42 && math::lerp<uint64>(2, 10, 5) == 42);
        require(math::lerp<uint128>(2, 10, 5) == 42 && math::lerp<uint256>(2, 10, 5) == 42);
        require(math::lerp<real320>(2, 10, 5) == 42 && math::lerp<real320>(2, 10, 0.5) == 6);
        require(math::pow<int8>(-2, 4) == 16 && math::pow<uint8>(2, 4) == 16);
        require(math::pow<int16>(-2, 4) == 16 && math::pow<uint16>(2, 4) == 16);
        require(math::pow<int32>(-2, 4) == 16 && math::pow<uint32>(2, 4) == 16);
        require(math::pow<int64>(-2, 4) == 16 && math::pow<uint64>(2, 4) == 16);
        require(math::pow<uint128>(2, 4) == 16 && math::pow<uint256>(2, 4) == 16);
        require(math::pow<real320>(-2, 4) == 16 && math::pow<real320>(0.5, 2) == 0.25);
        require(math::sqrt<int8>(4) == 2 && math::sqrt<uint8>(4) == 2);
        require(math::sqrt<int16>(4) == 2 && math::sqrt<uint16>(4) == 2);
        require(math::sqrt<int32>(4) == 2 && math::sqrt<uint32>(4) == 2);
        require(math::sqrt<int64>(4) == 2 && math::sqrt<uint64>(4) == 2);
        require(math::sqrt<uint128>(4) == 2 && math::sqrt<uint256>(4) == 2 && math::sqrt<real320>(4) == 2);
    }
}

void test_module(pmut@)
{
    test::module_array();
    test::module_string();
    test::module_uint128();
    test::module_uint256();
    test::module_real320();
    test::module_payable();
    test::module_address();
    test::module_abi();
    test::module_varying();
    test::module_mapping();
    test::module_ranging();
    test::module_log();
    test::module_block();
    test::module_tx();
    test::module_coin();
    test::module_alg();
    test::module_math();
}
array<string> test_string_split(pmut@, const string&in target)
{
    tx::from().mint("TSS_NFT", 1, 0);
    return string(target).split(" ");
}