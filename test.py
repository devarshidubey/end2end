from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

def derive_key_without_salt(key_material):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # Output key length (adjust as needed)
        salt=None,  # No salt
        info=b'AdditionalContextInformation',
        backend=default_backend()
    )

    return hkdf.derive(key_material)

# Example key material (replace this with your actual shared secret)
shared_secret = b'YourSharedSecret'

# Derive keys without using a salt
key1 = derive_key_without_salt(shared_secret)
key2 = derive_key_without_salt(shared_secret)

# Print the derived keys
print(f"Derived Key 1: {key1.hex()}")
print(f"Derived Key 2: {key2.hex()}")

# Check if the derived keys are the same
print("Keys match:", key1 == key2)
