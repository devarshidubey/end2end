from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import binascii

def generate_keys():
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key
