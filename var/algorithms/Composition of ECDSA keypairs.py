# Composition of ECC keypairs for trustless asset storage
# - uses two parties to compute a shared public key
# - shared public key can be used to derive a wallet address (PKH)
# - wallet address can be used to lock assets
# - when assets should be unlocked one party reveals their part of secret key
# - when too secret keys are combined the shared secret key is derived
# - party that has derived the second secret key may send assets to their wallet and dispose of this wallet

def setup(entropy):
  secret_key_1 = ecc::keygen(entropy)        # Derive a secret key 1 from entropy
  public_key_1 = ecc::derive64(secret_key_1) # Derive uncompressed public key 1 from secret key 1 (if less than 64 bytes then last 32 bytes are random)
  return {
    secret_key_1: secret_key_1
    public_key_1: public_key_1
  }

def seal(entropy, public_key_1):
  secret_key_2 = ecc::keygen(entropy)                                                                                # Derive a secret key 2 from entropy
  public_key_2 = ecc::derive64(secret_key_2)                                                                         # Derive uncompressed public key 2 from secret key 2

  scalar_x = hash256(public_key_1[0..32], public_key_2[0..32])                                                       # Derive scalar X from hashing first 32 bytes of public key 1 then updating with hash of first 32 bytes of public key 2
  while not ecc::verify_secret_key(scalar_x):                                                                        # If scalar X is not a valid private key then hash it
    scalar_x = hash256(scalar_x)

  scalar_y = hash256(public_key_1[32..64], public_key_2[32..64])                                                     # Derive scalar Y from hashing last 32 bytes of public key 1 then updating with hash of last 32 bytes of public key 2
  while not ecc::verify_secret_key(scalar_y):                                                                        # If scalar Y is not a valid private key then hash it
    scalar_y = hash256(scalar_y)

  shared_public_key = ecc::point_add(ecc::point_mul(ecc::point_add(public_key_1, scalar_x), secret_key_2), scalar_y) # Derive a shared public key from public key 1, scalar x, secret key 2 and scalar Y
  return {
    secret_key_2: secret_key_2,
    public_key_2: public_key_2,
    shared_public_key: shared_public_key
  }

def open(secret_key_1, secret_key_2):
  public_key_1 = ecc::derive64(secret_key_1)                                                                            # Derive uncompressed public key 1 from secret key 1
  public_key_2 = ecc::derive64(secret_key_2)                                                                            # Derive uncompressed public key 2 from secret key 2

  scalar_x = hash256(public_key_1[0..32], public_key_2[0..32])                                                          # Derive a scalar X
  while not ecc::verify_secret_key(scalar_x):
    scalar_x = hash256(scalar_x)

  scalar_y = hash256(public_key_1[32..64], public_key_2[32..64])                                                        # Derive a scalar Y
  while not ecc::verify_secret_key(scalar_y):
    scalar_y = hash256(scalar_y)

  shared_secret_key = ecc::scalar_add(ecc::scalar_mul(ecc::scalar_add(secret_key_1, scalar_x), secret_key_2), scalar_y) # Derive a shared secret key from secret key 1, scalar x, secret key 2 and scalar Y
  return shared_secret_key