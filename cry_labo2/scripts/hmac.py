from Crypto.Cipher import AES
from Crypto import Random
from base64 import b64encode, b64decode
from Crypto.Util.strxor import strxor
import sys


def pad(m):
    m += b"\x80"
    while len(m) % 16 != 0:
        m+= b"\x00"
    return m

def h(m, k):
    m = pad(m)
    blocks = [m[i:i + 16] for i in range(0, len(m), 16)]
    h = k
    for i in range(len(blocks)):
        h = strxor(AES.new(blocks[i], AES.MODE_ECB).encrypt(h), h)
    return h 

def mac(message, key):
    return h(message, key)
def verify(message, key, tag):
    return mac(message, key) == tag
def create_new_message(m, previous_mac, new_amount):
    m = pad(m)
    m += new_amount
    mPrime = m
    m = pad(m)
    blocks = [m[i:i + 16] for i in range(0, len(m), 16)]
    # calculate the new mac for the last new block that has been added
    h = previous_mac
    h = strxor(AES.new(blocks[-1], AES.MODE_ECB).encrypt(h), h)
    return h, mPrime
def ex():
    k = Random.get_random_bytes(16)
    m = b"Sender: Alexandre Duc; Destination account 12-1234-12. Amount CHF123"
    mc =  mac(m, k)
    newMac, mPrime = create_new_message(m, mc, b"800")
    print("m = %s" % m)
    print("m prime = %s" % mPrime)
    print("verify original message with key = %s" % verify(m, k, mc))
    print("verify m prime with original key = %s" % verify(mPrime, k, newMac))
    pretty_print(mPrime)

    key = b'change to your k'
    mc = b64decode(b'G5Rr9zn8+YEAR4bWd6cbrg==')

    newMac, mPrime = create_new_message(m, mc, b"800")

    print("verify with your key = %s" % verify(mPrime, key, newMac))

    pretty_print(mPrime)


#m has to be a bytestring
def pretty_print(m):
    print(m.decode("UTF-8", errors="ignore"))

ex()