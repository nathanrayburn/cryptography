import hashlib
import os

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from dataclass import user
from dataclass import msg

Message = msg.Message
User = user.User

def hash_user_key(userkey):
    """
    \brief Hashes a user key using HKDF.
    \param userkey The user key to hash.
    \return The hashed user key.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"server-pwd-hash",
        backend=default_backend()
    )
    return hkdf.derive(userkey)

def derive_user_key_from_password(username, password):
    """
    \brief Derives a user key from a password using Argon2id.
    \param username The username to derive the salt.
    \param password The password to derive the key.
    \return The derived user key.
    """
    salt = derive_salt_from_username(username)
    user_key = hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=5,
        memory_cost=2**16,
        parallelism=1,
        hash_len=32,
        type=Type.ID
    )
    return user_key

def derive_salt_from_username(username):
    """
    \brief Derives a salt from a username using HKDF.
    \param username The username to derive the salt.
    \return The derived salt.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"password-salt",
        backend=default_backend()
    )
    return hkdf.derive(username.encode())

def generate_identity_keypair():
    """
    \brief Generates an identity key pair using ECDSA.
    \return The generated private and public keys.
    """
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def generate_ephemeral_keypair():
    """
    \brief Generates an ephemeral key pair using ECDSA.
    \return The generated private and public keys.
    """
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def compute_shared_secret(private_key, peer_public_key):
    """
    \brief Computes a shared secret using ECDH.
    \param private_key The private key.
    \param peer_public_key The peer's public key.
    \return The computed shared secret.
    """
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    return shared_secret

def export_private_key_to_bytes(private_key):
    """
    \brief Exports a private key to bytes.
    \param private_key The private key to export.
    \return The private key in bytes.
    """
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return private_key_bytes

def export_public_key_to_bytes(public_key):
    """
    \brief Exports a public key to bytes.
    \param public_key The public key to export.
    \return The public key in bytes.
    """
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return public_key_bytes

def import_private_key_from_bytes(private_key_bytes):
    """
    \brief Imports a private key from bytes.
    \param private_key_bytes The private key in bytes.
    \return The imported private key.
    """
    private_key = serialization.load_pem_private_key(
        private_key_bytes,
        password=None,
        backend=default_backend()
    )
    return private_key

def import_public_key_from_bytes(public_key_bytes):
    """
    \brief Imports a public key from bytes.
    \param public_key_bytes The public key in bytes.
    \return The imported public key.
    """
    public_key = serialization.load_pem_public_key(
        public_key_bytes,
        backend=default_backend()
    )
    return public_key

def encrypt_message(encryption_key, plaintext):
    """
    \brief Encrypts a message using ChaCha20-Poly1305.
    \param encryption_key The encryption key.
    \param plaintext The plaintext message.
    \return The nonce and ciphertext.
    """
    nonce = os.urandom(12)
    cipher = ChaCha20Poly1305(encryption_key)
    ciphertext = cipher.encrypt(nonce, plaintext, None)
    return nonce, ciphertext

def decrypt_message(encryption_key, nonce, ciphertext):
    """
    \brief Decrypts a message using ChaCha20-Poly1305.
    \param encryption_key The encryption key.
    \param nonce The nonce used for encryption.
    \param ciphertext The encrypted message.
    \return The decrypted plaintext message.
    """
    cipher = ChaCha20Poly1305(encryption_key)
    plaintext = cipher.decrypt(nonce, ciphertext, None)
    return plaintext

def derive_encryption_key(shared_secret):
    """
    \brief Derives an encryption key from a shared secret using HKDF.
    \param shared_secret The shared secret.
    \return The derived encryption key.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"dh-ratchet",
        backend=default_backend()
    )
    encryption_key = hkdf.derive(shared_secret)
    return encryption_key

def sender_workflow(receiver_public_key, plaintext):
    """
    \brief Performs the sender's workflow for encrypting a message.
    \param receiver_public_key The receiver's public key.
    \param plaintext The plaintext message.
    \return The sender's ephemeral public key, nonce, and ciphertext.
    """
    sender_private_key, sender_public_key = generate_ephemeral_keypair()
    shared_secret = compute_shared_secret(sender_private_key, receiver_public_key)
    encryption_key = derive_encryption_key(shared_secret)
    nonce, ciphertext = encrypt_message(encryption_key, plaintext)
    return sender_public_key, nonce, ciphertext

def receiver_workflow(receiver_private_key, sender_public_key, nonce, ciphertext):
    """
    \brief Performs the receiver's workflow for decrypting a message.
    \param receiver_private_key The receiver's private key.
    \param sender_public_key The sender's public key.
    \param nonce The nonce used for encryption.
    \param ciphertext The encrypted message.
    \return The decrypted plaintext message.
    """
    shared_secret = compute_shared_secret(receiver_private_key, sender_public_key)
    encryption_key = derive_encryption_key(shared_secret)
    plaintext = decrypt_message(encryption_key, nonce, ciphertext)
    return plaintext

def hash_password(password: bytes) -> bytes:
    """
    \brief Hashes a password using SHA3-512.
    \param password The password to hash.
    \return The hashed password.
    """
    sha3_hasher = hashlib.sha3_512()
    sha3_hasher.update(password)
    return sha3_hasher.digest()