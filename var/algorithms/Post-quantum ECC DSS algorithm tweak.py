# Post-quantum ECC DSS algorithm tweak
# - applicable to most ECC DSS algorithms
# - applicable to existing projects using ECC DSS (eg. blockchains like Bitcoin, Ethereum, Ripple, etc.)
# - requires a change to functions: SIGN_MSG(MSG, SK), RECOVER_SIG_PK(MSG, SIG), VERIFY_SIG(MSG, SIG, PK)
# - requires a change to use a tweaked public key instead of public key derived from secret key
# - does not require any more space than a normal ECC algorithm (secret key - 32 bytes, public key - 32/33/64/65 bytes, public key hash - 20 bytes, signature - 64/65 bytes)
# - does not reveal a root keypair by using one time signature keypairs
# - does not require any additional dependencies other than already used ECC and hashing libraries
# - root public key is can only be revealed when secret key is given
# - public key hash is always computable from root keypair or any of previous signature (given the signature is recoverable)
# - public key hash is not a direct hash of root public key rather a hash of tweaked public key
# - signable message should be unique (input/output transaction hash for Bitcoin or transaction nonce for Ethereum)
# - signature requires a root secret key to sign
# - signature uses a one time keypair derived from root secret key and public parameters
# - signature keypair could be compromised by Shor's algorithm but it will not help to recover the root keypair
# - signature recovers a one time public key that if tweaked will recover root public key hash without revealing root public key
# - tweaked root public key when revealed can be compromised by Shor's algorithm to recover a tweaked root secret key which is unused in this DSS tweak
# - root public key when must not be revealed if environment is vulnerable to Shor's algorithm (pk will be dsk - derivative of secret key)
# - other properties are exactly the same as in any other ECC algorithms

def BLINDING_SCALAR(INPUT):
  SCALAR = HASH256(INPUT)                    # Derive a tweak by hashing the input
  while not ECC::VERIFY_SECRET_KEY(SCALAR):  # If tweak is not a valid private key then hash it again
    SCALAR = HASH256(SCALAR)
  return SCALAR

def BLINDING_TWEAK_ALPHA(SECRET_KEY, PUBLIC_KEY):
  TWEAK_DERIVATIVE = ECC::POINT_MULTIPLY(PUBLIC_KEY, SECRET_KEY) # Calculate tweak derivative by point multiplying a root public key by a root secret key
  TWEAK_ALPHA = BLINDING_SCALAR(TWEAK_DERIVATIVE)                # Derive a tweak alpha by blinding the tweak derivative
  return TWEAK_ALPHA

def BLINDING_TWEAK_BETA(PUBLIC_KEY):
  TWEAK_BETA = BLINDING_SCALAR(PUBLIC_KEY) # Derive a tweak beta by hashing the root public key
  return TWEAK_BETA

def BLINDING_TWEAK_GAMMA(MESSAGE_HASH256):
  SCALAR_ALPHA = BLINDING_SCALAR(MESSAGE_HASH256)                # Derive a scalar alpha by blinding the message hash
  SCALAR_BETA = BLINDING_SCALAR(SCALAR_ALPHA)                    # Derive a scalar beta by blinding the scalar alpha
  TWEAK_GAMMA = ECC::SCALAR_MULTIPLY(SCALAR_ALPHA, SCALAR_BETA)  # Derive a tweak gamma by scalar multiplying scalar alpha by scalar beta
  return TWEAK_GAMMA

def BLINDING_KEYPAIR(ENTROPY):
  ROOT_SECRET_KEY = ECC::KEYGEN(ENTROPY)                                 # Derive a root secret key from entropy
  ROOT_PUBLIC_KEY = ECC::DERIVE(ROOT_SECRET_KEY)                         # Derive a root public key from secret key
  TWEAK_ALPHA = BLINDING_TWEAK_ALPHA(ROOT_SECRET_KEY, ROOT_PUBLIC_KEY)   # Derive a tweak alpha from root secret key
  TWEAK_BETA = BLINDING_TWEAK_BETA(ROOT_PUBLIC_KEY)                      # Derive a tweak beta from root public key
  TWEAK_DERIVATIVE = ECC::POINT_ADD(ROOT_PUBLIC_KEY, TWEAK_ALPHA)        # Calculate a tweak derivative by point adding root public key and tweak alpha
  TWEAKED_PUBLIC_KEY = ECC::POINT_MULTIPLY(TWEAK_DERIVATIVE, TWEAK_BETA) # Derive a tweaked public key from point multiplying tweak derivative by tweak beta
  TWEAKED_PUBLIC_KEY_HASH = HASH160(TWEAKED_PUBLIC_KEY)                  # Derive a tweaked public key hash by hashing the tweaked public key
  return {
    SECRET_KEY: ROOT_SECRET_KEY,
    PUBLIC_KEY: TWEAKED_PUBLIC_KEY,
    ADDRESS: TWEAKED_PUBLIC_KEY_HASH
  }


def BLINDING_SIGN(MESSAGE_HASH256, SECRET_KEY):
  ROOT_PUBLIC_KEY = ECC::DERIVE(ROOT_SECRET_KEY)                              # Derive a root public key from secret key
  TWEAK_ALPHA = BLINDING_TWEAK_ALPHA(ROOT_SECRET_KEY, ROOT_PUBLIC_KEY)        # Derive a tweak alpha from root secret key
  TWEAK_BETA = BLINDING_TWEAK_BETA(ROOT_PUBLIC_KEY)                           # Derive a tweak beta from root public key
  TWEAK_GAMMA = BLINDING_TWEAK_GAMMA(MESSAGE_HASH256)                         # Derive a tweak gamma from message
  TWEAK_DERIVATIVE = ECC::SCALAR_ADD(ROOT_SECRET_KEY, TWEAK_ALPHA)            # Calculate a tweak derivative by scalar adding root secret key and tweak alpha
  TWEAKED_SECRET_KEY = ECC::SCALAR_MULTIPLY(TWEAK_DERIVATIVE, TWEAK_BETA)     # Calculate a tweaked secret key by scalar multiplying tweak derivative 1 by tweak beta
  SIGNATURE_SECRET_KEY = ECC::SCALAR_ADD(TWEAKED_SECRET_KEY, TWEAK_GAMMA)     # Derive a signature secret key by scalar adding tweaked secret key and tweak gamma
  (SIGNATURE, RECOVERY_ID) = ECC::SIGN(MESSAGE_HASH256, SIGNATURE_SECRET_KEY) # Sign a message hash with signature secret key
  return {
    SIGNATURE: SIGNATURE,
    RECOVERY_ID: RECOVERY_ID
  }

def BLINDING_VERIFY(MESSAGE_HASH256, SIGNATURE, PUBLIC_KEY):
  TWEAK_GAMMA = BLINDING_TWEAK_GAMMA(MESSAGE_HASH256)                   # Derive a tweak gamma from message
  SIGNATURE_PUBLIC_KEY = ECC::POINT_ADD(PUBLIC_KEY, TWEAK_GAMMA)        # Derive a signature public key from tweaked public key by point adding tweaked public key with tweak gamma
  VALID = ECC::VERIFY(MESSAGE_HASH256, SIGNATURE, SIGNATURE_PUBLIC_KEY) # Verify signature with signature public key
  return VALID

def BLINDING_RECOVER(MESSAGE_HASH256, SIGNATURE, RECOVERY_ID):
  SIGNATURE_PUBLIC_KEY = ECC::RECOVER(MESSAGE_HASH256, SIGNATURE, RECOVERY_ID) # Recover a signature public key from signature using recovery id
  if not ECC::VERIFY_PUBLIC_KEY(SIGNATURE_PUBLIC_KEY):                         # If recovered public key is not valid then signature is not valid
    return None
  
  TWEAK_GAMMA = BLINDING_TWEAK_GAMMA(MESSAGE_HASH256)                          # Derive a tweak gamma from message
  TWEAKED_PUBLIC_KEY = ECC::POINT_SUBTRACT(SIGNATURE_PUBLIC_KEY, TWEAK_GAMMA)  # Derive a tweaked public key by point adding signature public key with a negative of tweak gamma
  TWEAKED_PUBLIC_KEY_HASH = HASH160(TWEAKED_PUBLIC_KEY)                        # Derive a tweaked public key hash by hashing the tweaked public key
  return {
    PUBLIC_KEY: TWEAKED_PUBLIC_KEY,
    ADDRESS: TWEAKED_PUBLIC_KEY_HASH
  }