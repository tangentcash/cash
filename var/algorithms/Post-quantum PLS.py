def curve():
    c = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff43
    return c

def secret_key(d):
    x = hash256(d)
    y = [](256)
    map[0..256] => (i):
        ky = x[i mod 32]
        kx = map[x] => (j):
            <= x[j] xor ky
        <= y[i] = hash160(i | kx | ky)
    return [x, y]

def public_key(y):
    c = curve()
    z = reduce[y, p = 1] => (i):
        <= p * y[i] mod c
    return hash256(z)

def sign(m, y):
    c = curve()
    e = hash256(m)
    sy = distinct map[e] => (i):
        <= y[e[i]]
    ry = reduce map[y] => (i):
        <= y[i] not in sy
    sp = reduce[sy, p = 1] => (i):
        <= p * sy[i] mod c
    rp = reduce[ry, p = 1] => (i):
        <= p * ry[i] mod c
    return [s, r]

def verify(m, s, r, z):
    c = curve()
    e = hash256(m)
    a = s * r mod c
    b = m * e * z mod c
    return a is b