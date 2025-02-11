from base64 import b64decode

from Crypto.Cipher import AES

NONCE_LENGTH = 12
p = 340282366920938463463374607431768211507  # prime number


def bytesToInt(message):
    return int.from_bytes(message, "big")


def intToBytes(i):
    return int(i).to_bytes(16, "big")


# Compute the mac of message under key with nonce.
# It is similar to Poly1305
def mac(nonce, message, key):
    cipher = AES.new(key, mode=AES.MODE_ECB)
    v = bytesToInt(cipher.encrypt(b"\xff" * 16))
    blocks = [message[i:i + 16] for i in range(0, len(message), 16)]
    temp = 0
    for b in blocks:
        temp = (temp + bytesToInt(b) * v) % p
    temp = (temp + bytesToInt(cipher.encrypt(nonce + b"\x00" * (16 - NONCE_LENGTH)))) % p
    return intToBytes(temp)


# Encrypts the message under key with nonce.
# It is an improved CTR that exploits the power of prime numbers
def encrypt(nonce, message, key):
    ct = b""
    for i in range(len(message) // 16):
        cipher = AES.new(key, mode=AES.MODE_CTR, nonce=nonce)
        keystream = cipher.encrypt(b"\x00" * 16)  # Way to obtain keystream: we XOR with 0
        temp = (bytesToInt(message[16 * i:16 * (i + 1)]) + bytesToInt(keystream)) % p
        ct += intToBytes(temp)
    return ct


# Encrypt and MAC with the fixed algorithm
def encryptAndMac(nonce, message, key):
    ct = encrypt(nonce, message, key)
    tag = mac(nonce, message, key)
    return (ct, tag)


def mod_inverse(x, mod):
    return pow(x, -1, mod)


'''
    m1: the first message
    nonce1: the nonce used to encrypt m1
    tag1: the tag of m1
    c1: the encryption of m1
    nonce2: the nonce used to encrypt m2
    tag2: the tag of m2
    c2: the encryption of m2
    This function is designed to crack the encryption of m2
'''


def crack_encryption(m1, nonce1, tag1, c1, nonce2, tag2, c2):
    print("Cracking the encryption of the second message...")
    # Decode c1 and c2 from base64
    c1 = b64decode(c1)
    c2 = b64decode(c2)
    tag1 = b64decode(tag1)
    tag2 = b64decode(tag2)

    # Split m1, c1_decoded and c2_decoded into blocks
    m1_blocks = [m1[i:i + 16] for i in range(0, len(m1), 16)]
    c1_blocks = [c1[i:i + 16] for i in range(0, len(c1), 16)]
    c2_blocks = [c2[i:i + 16] for i in range(0, len(c2), 16)]

    # find sigma for the first message
    sigma = (bytesToInt(c1_blocks[0]) - bytesToInt(m1_blocks[0])) % p

    sumM1 = sum([bytesToInt(m1_blocks[i]) for i in range(len(m1_blocks))]) % p
    sumC2 = sum([bytesToInt(c2_blocks[i]) for i in range(len(c2_blocks))]) % p

    # find v
    v = ((bytesToInt(tag1) - sigma) * mod_inverse(sumM1, p)) % p



    # length of c2_blocks
    n = len(c2_blocks)
    # find sigma for the second message
    sigma2 = (bytesToInt(tag2) - v*sumC2) * mod_inverse(1 - v*n, p) % p

    plaintext2 = b""
    for i, val in enumerate(c2_blocks):
        plaintext2 += intToBytes((bytesToInt(val) - sigma2) % p)  # Decryption
    print("Plaintext 2 = ", plaintext2)
    return plaintext2


m1 = b'ICRYInTheMorning'
nonce1 = b'LIrYgrQrcRZK/BnQ'
c1 = b'AdQMOX+adEHQnD3rw4Xjuw=='
tag1 = b'o5cixYgeS8CEifizc6cEuQ=='
nonce2 = b'gxRletwmC0f0HOGF'
c2 = b'Z4OCArnWY5p2DYGOpjmn1IeGeQ9n3mJHuFyni6+CotY='
tag2 = b'Tn9i1z9LalSEg8NQz1Uujw=='

crack_encryption(m1, nonce1, tag1, c1, nonce2, tag2, c2)