# Composition of ECC keypairs for trustless asset storage
# - uses two parties to compute a shared public key
# - shared public key can be used to derive a wallet address (PKH)
# - wallet address can be used to lock assets
# - when assets should be unlocked one party reveals their part of secret key
# - when to secret keys are combined the shared secret key is derived
# - party that has derived the second secret key may send assets to their wallet and dispose of this wallet

def KEYPAIR1(ENTROPY):
  SECRET_KEY_1 = ECC::KEYGEN(ENTROPY)        # Derive a secret key 1 from entropy
  PUBLIC_KEY_1 = ECC::DERIVE64(SECRET_KEY_1) # Derive uncompressed public key 1 from secret key 1 (if less than 64 bytes then last 32 bytes are random)
  return {
    SECRET_KEY_1: SECRET_KEY_1
    PUBLIC_KEY_1: PUBLIC_KEY_1
  }

def KEYPAIR2(ENTROPY, PUBLIC_KEY_1):
  SECRET_KEY_2 = ECC::KEYGEN(ENTROPY)                                                                                     # Derive a secret key 2 from entropy
  PUBLIC_KEY_2 = ECC::DERIVE64(SECRET_KEY_2)                                                                              # Derive uncompressed public key 2 from secret key 2

  SCALAR_X = HASH256(PUBLIC_KEY_1[0..32], PUBLIC_KEY_2[0..32])                                                            # Derive scalar X from hashing first 32 bytes of public key 1 then updating with hash of first 32 bytes of public key 2
  while not ECC::VERIFY_SECRET_KEY(SCALAR_X):                                                                             # If scalar X is not a valid private key then hash it
    SCALAR_X = HASH256(SCALAR_X)

  SCALAR_Y = HASH256(PUBLIC_KEY_1[32..64], PUBLIC_KEY_2[32..64])                                                          # Derive scalar Y from hashing last 32 bytes of public key 1 then updating with hash of last 32 bytes of public key 2
  while not ECC::VERIFY_SECRET_KEY(SCALAR_Y):                                                                             # If scalar Y is not a valid private key then hash it
    SCALAR_Y = HASH256(SCALAR_Y)

  SHARED_PUBLIC_KEY = ECC::POINT_ADD(ECC::POINT_MULTIPLY(ECC::POINT_ADD(PUBLIC_KEY_1, SCALAR_X), SECRET_KEY_2), SCALAR_Y) # Derive a shared public key from public key 1, scalar x, secret key 2 and scalar Y
  return {
    SECRET_KEY_2: SECRET_KEY_2,
    PUBLIC_KEY_2: PUBLIC_KEY_2,
    SHARED_PUBLIC_KEY: SHARED_PUBLIC_KEY
  }

def KEYREVEAL(SECRET_KEY_1, SECRET_KEY_2):
  PUBLIC_KEY_1 = ECC::DERIVE64(SECRET_KEY_1)                                                                                 # Derive uncompressed public key 1 from secret key 1
  PUBLIC_KEY_2 = ECC::DERIVE64(SECRET_KEY_2)                                                                                 # Derive uncompressed public key 2 from secret key 2

  SCALAR_X = HASH256(PUBLIC_KEY_1[0..32], PUBLIC_KEY_2[0..32])                                                               # Derive a scalar X
  while not ECC::VERIFY_SECRET_KEY(SCALAR_X):
    SCALAR_X = HASH256(SCALAR_X)

  SCALAR_Y = HASH256(PUBLIC_KEY_1[32..64], PUBLIC_KEY_2[32..64])                                                             # Derive a scalar Y
  while not ECC::VERIFY_SECRET_KEY(SCALAR_Y):
    SCALAR_Y = HASH256(SCALAR_Y)

  SHARED_SECRET_KEY = ECC::SCALAR_ADD(ECC::SCALAR_MULTIPLY(ECC::SCALAR_ADD(SECRET_KEY_1, SCALAR_X), SECRET_KEY_2), SCALAR_Y) # Derive a shared secret key from secret key 1, scalar x, secret key 2 and scalar Y
  return SHARED_SECRET_KEY