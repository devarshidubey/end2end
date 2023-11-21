from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

def sign_data(data, private_key):
    signature = private_key.sign(
        data,
        algorithm=hashes.SHA256()
    )
    return signature

def verify_signature(public_key, data, signature):
    try:
        public_key.verify(
            signature,
            data,
            algorithm=hashes.SHA256()
        )
        return True
    except:
        return False
