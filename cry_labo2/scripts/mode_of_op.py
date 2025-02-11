from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util.strxor import strxor
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode


def encrypt(message, key):
    # pad the message
    message = pad(message, 16)

    cipher = AES.new(key, mode=AES.MODE_ECB)

    IV = Random.get_random_bytes(16)
    ciphertext = [IV]
    # First block
    m1 = message[:16]
    t = cipher.encrypt(m1)
    c1 = strxor(t, IV)
    ciphertext.append(c1)
    # Remaining blocks don't have an IV
    message_blocks = [message[16 * (i + 1):16 * (i + 2)] for i in range(len(message) // 16 - 1)]
    for m in message_blocks:
        t = cipher.encrypt(t)
        c = strxor(t, m)
        ciphertext.append(c)

    return b"".join(ciphertext)


def decrypt(ciphertext, key):
    cipher = AES.new(key, mode=AES.MODE_ECB)
    IV = ciphertext[:16]

    t = strxor(ciphertext[16:32], IV)

    m1 = cipher.decrypt(t)

    message = [m1]
    message_blocks = [ciphertext[16 * (i + 2):16 * (i + 3)] for i in range(len(ciphertext) // 16 - 2)]

    for c in message_blocks:
        t = cipher.encrypt(t)
        m = strxor(t, c)
        message.append(m)
    return unpad(b"".join(message), 16)

def split_into_blocks(message, block_size=16):
    return [message[i:i + block_size] for i in range(0, len(message), block_size)]
def crack(m1, c1, c2):

    m1 = pad(m1, 16)

    m1_blocks = split_into_blocks(m1)
    c1_blocks = split_into_blocks(c1)
    c2_blocks = split_into_blocks(c2)

    m2_blocks = [m1_blocks[0]]

    t_1 = strxor(c1_blocks[0], c1_blocks[1])
    t_2 = strxor(c2_blocks[0], c2_blocks[1])

    if t_1 == t_2:
        t_blocks = []
        c1_blocks = c1_blocks[2:]
        c2_blocks = c2_blocks[2:]
        m1_blocks = m1_blocks[1:]

        for (c1_block, m1_block), c2_block in zip(zip(c1_blocks, m1_blocks), c2_blocks):
            t_block = strxor(c1_block, m1_block)
            m2_block = strxor(t_block, c2_block)
            t_blocks.append(t_block)
            m2_blocks.append(m2_block)

    return b"".join(m2_blocks)


def test():
    key = Random.get_random_bytes(16)
    m1 = b"This is a long enough test message to check that everything is working fine and it does. This algorithm is super secure and we will try to sell it soon to the Swiss governement."
    c1 = encrypt(m1, key)
    print(b64encode(c1))
    print(decrypt(c1, key))

    c1 = b'oovMoosEIUWgDH+EIIZVi4NWaVxpvkln1BDS23ZYXJhfa/CX7zHqQDGYpTwPP0Q4OPhgwZQxGy04CI2j1lShJci/5pN52OB8CEjz6mBNXrdlmrm2sWrEfQvBpOrc2Oo+AZz4B2LzBMB6Tkh0pceiEyIQjLWSasKXPdpEk+pHqx7w1WGTCDMhNpo8PsblPXGigg2QCazSIWVkutcwojDUdVyGtQS1bF4iCUUcxFfdCou4o/wkQ9bxITvNtwYL/c/oyrjvFSQOk6wl1MQJAoi+qQ=='
    c2 = b'6fNXqn0I2jTyVrutk9KfM8gu8lSfsrIWhkoW8sUMliBfa/CX7zHzQDGf5DYPbFE2Lb0pwdtlF2U/Dsbwx1+1I430sKJjxLRnBEXmr30eGKxrj/K2rC2IehfdpKbOtY0d'
    c1_decoded = b64decode(c1)
    c2_decoded = b64decode(c2)
    plaintext = crack(m1,c1_decoded, c2_decoded)
    print(plaintext)

test()
