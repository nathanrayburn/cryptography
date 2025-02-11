from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives import hashes

def sign_message(private_key, message):
    """
    \brief Sign the message with the sender's private key.
    \param private_key The private key used to sign the message.
    \param message The message to be signed.
    \return The generated signature.
    """
    signature = private_key.sign(
        message,
        ec.ECDSA(hashes.SHA3_512())
    )
    return signature

def verify_signature(public_key, message, signature):
    """
    \brief Verify the message signature with the sender's public key.
    \param public_key The public key used to verify the signature.
    \param message The message whose signature is to be verified.
    \param signature The signature to be verified.
    \return True if the signature is valid, False otherwise.
    """
    try:
        public_key.verify(
            signature,
            message,
            ec.ECDSA(hashes.SHA3_512())
        )
        return True
    except Exception:
        return False