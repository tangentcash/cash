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

def BLINDING_TWEAK_RT(PUBLIC_KEY):
  ROOT_TWEAK = HASH256(PUBLIC_KEY)              # Derive a root tweak by hashing the root public key
  while not ECC::VERIFY_SECRET_KEY(ROOT_TWEAK): # If root tweak is not a valid private key then hash it again
    ROOT_TWEAK = HASH256(ROOT_TWEAK)
  return ROOT_TWEAK

def BLINDING_KEYPAIR(ENTROPY):
  ROOT_SECRET_KEY = ECC::KEYGEN(ENTROPY)                                # Derive a root secret key from entropy
  ROOT_PUBLIC_KEY = ECC::DERIVE(ROOT_SECRET_KEY)                        # Derive a root public key from secret key
  ROOT_TWEAK = BLINDING_TWEAK_RT(ROOT_PUBLIC_KEY)                       # Derive a root tweak by hashing the root public key
  TWEAKED_PUBLIC_KEY = ECC::POINT_MULTIPLY(ROOT_PUBLIC_KEY, ROOT_TWEAK) # Derive a tweaked public key from point multiplying root public key by root tweak
  TWEAKED_PUBLIC_KEY_HASH = HASH160(TWEAKED_PUBLIC_KEY)                 # Derive a tweaked public key hash by hashing the tweaked public key
  return {
    SECRET_KEY: ROOT_SECRET_KEY,
    PUBLIC_KEY: TWEAKED_PUBLIC_KEY,
    ADDRESS: TWEAKED_PUBLIC_KEY_HASH
  }

def BLINDING_TWEAK_ST(MESSAGE_HASH32):
  SIGNATURE_TWEAK_A = MESSAGE_HASH32                                           # Assign tweak A to hash of a message
  while not ECC::VERIFY_SECRET_KEY(SIGNATURE_TWEAK_A):                         # If tweak A is not a valid private key then hash it
    SIGNATURE_TWEAK_A = HASH256(SIGNATURE_TWEAK_A)

  SIGNATURE_TWEAK_B = HASH256(SIGNATURE_TWEAK_A)                               # Assign tweak B to hash of tweak A
  while not ECC::VERIFY_SECRET_KEY(SIGNATURE_TWEAK_B):                         # If tweak B is not a valid private key then hash it again
    SIGNATURE_TWEAK_B = HASH256(SIGNATURE_TWEAK_B)

  SIGNATURE_TWEAK = ECC::SCALAR_MULTIPLY(SIGNATURE_TWEAK_A, SIGNATURE_TWEAK_B) # Derive a signature tweak by scalar multiplying tweak A by tweak B
  return SIGNATURE_TWEAK


def BLINDING_SIGN(MESSAGE_HASH32, SECRET_KEY):
  SIGNATURE_TWEAK = BLINDING_TWEAK_ST(MESSAGE_HASH32)                                                        # Derive a signature tweak from message
  ROOT_PUBLIC_KEY = ECC::DERIVE(ROOT_SECRET_KEY)                                                             # Derive a root public key from secret key
  ROOT_TWEAK = BLINDING_TWEAK_RT(ROOT_PUBLIC_KEY)                                                            # Derive a root tweak by hashing the root public key
  SIGNATURE_SECRET_KEY = ECC::SCALAR_ADD(ECC::SCALAR_MULTIPLY(ROOT_SECRET_KEY, ROOT_TWEAK), SIGNATURE_TWEAK) # Derive a signature secret key by scalar adding signature tweak to scalar multiplication of root secret key by root tweak
  (SIGNATURE, RECOVERY_ID) = ECC::SIGN(MESSAGE_HASH32, SIGNATURE_SECRET_KEY)                                 # Sign a message hash with signature secret key
  return {
    SIGNATURE: SIGNATURE,
    RECOVERY_ID: RECOVERY_ID
  }

def BLINDING_VERIFY(MESSAGE_HASH32, SIGNATURE, PUBLIC_KEY):
  SIGNATURE_TWEAK = BLINDING_TWEAK_ST(MESSAGE_HASH32)                  # Derive a signature tweak from message
  SIGNATURE_PUBLIC_KEY = ECC::POINT_ADD(PUBLIC_KEY, SIGNATURE_TWEAK)   # Derive a signature public key from tweaked public key by point adding tweaked public key with signature tweak
  VALID = ECC::VERIFY(MESSAGE_HASH32, SIGNATURE, SIGNATURE_PUBLIC_KEY) # Verify signature with signature public key
  return VALID

def BLINDING_RECOVER(MESSAGE_HASH32, SIGNATURE, RECOVERY_ID):
  SIGNATURE_PUBLIC_KEY = ECC::RECOVER(MESSAGE_HASH32, SIGNATURE, RECOVERY_ID)         # Recover a signature public key from signature using recovery id
  if not ECC::VERIFY_PUBLIC_KEY(SIGNATURE_PUBLIC_KEY):                                # If recovered public key is not valid then signature is not valid
    return None
  
  SIGNATURE_TWEAK = BLINDING_TWEAK_ST(MESSAGE_HASH32)                                 # Derive a signature tweak from message
  SIGNATURE_TWEAK_NEGATIVE = ECC::SCALAR_NEGATE(SIGNATURE_TWEAK)                      # Negate a signature tweak
  TWEAKED_PUBLIC_KEY = ECC::POINT_ADD(SIGNATURE_PUBLIC_KEY, SIGNATURE_TWEAK_NEGATIVE) # Derive a tweaked public key by point adding signature public key with a negative of signature tweak
  TWEAKED_PUBLIC_KEY_HASH = HASH160(TWEAKED_PUBLIC_KEY)                               # Derive a tweaked public key hash by hashing the tweaked public key
  return {
    PUBLIC_KEY: TWEAKED_PUBLIC_KEY,
    ADDRESS: TWEAKED_PUBLIC_KEY_HASH
  }