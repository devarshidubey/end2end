from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import hmac
import hashlib

def hkdf_sha256(rk, dh_out, info=b""):
    # HKDF-Extract
    prk = hmac.new(rk, dh_out, hashlib.sha256).digest()

    # HKDF-Expand
    output_key_material = hmac.new(prk, info + b"\x01", hashlib.sha256).digest()

    new_rk = output_key_material[:16]
    message_key = output_key_material[16:]

    return new_rk, message_key

class DoubleRatchet:
    def __init__(self, bob_dh_public_key, sk):
        local_private_key = x25519.X25519PrivateKey.generate()
        self.DHs = [local_private_key, local_private_key.public_key()]

        self.DHr = bob_dh_public_key

        self.root_key, self.CKs = hkdf_sha256(sk, local_private_key.exchange(self.DHr))
        self.CKr = None
        self.receiving_chain_key = None
        self.sending_message_key = None
        self.receiving_message_key = None

    def RatchetEncrypt(state, plaintext, AD):
        state.CKs, mk = hkdf_sha256(state.CKs, "hello world")
        header = HEADER(state.DHs, state.PN, state.Ns)
        state.Ns += 1
        return header, ENCRYPT(mk, plaintext, CONCAT(AD, header))

    
    def encrypt(self):
        