from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.backends import default_backend

def generate_keys():
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key

if __name__ == "__main__":
    ika_private, ika_public = generate_keys()
    ikb_private, ikb_public = generate_keys()

    spka_private, spka_public = generate_keys()
    spkb_private, spkb_public = generate_keys()

    eka_private, eka_public = generate_keys()
    ekb_private, ekb_public = generate_keys()

    dh1 = ika_private.exchange(spkb_public)
    dh2 = eka_private.exchange(ikb_public)
    dh3 = eka_private.exchange(spkb_public)

    result1 = dh1 + dh2 + dh3

    dh1 = spkb_private.exchange(ika_public)
    dh2 = ikb_private.exchange(eka_public)
    dh3 = spkb_private.exchange(eka_public)

    result2 = dh1 + dh2 + dh3

    if(result1 == result2):
        print(result1.hex())
        print(result2.hex())