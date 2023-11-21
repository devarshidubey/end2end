from cryptography.hazmat.primitives.asymmetric import x25519

alice_private_key = x25519.X25519PrivateKey.generate()
alice_public_key = alice_private_key.public_key()

bob_private_key = x25519.X25519PrivateKey.generate()
bob_public_key = bob_private_key.public_key()

shared1 = alice_private_key.exchange(bob_public_key)
shared2 = bob_private_key.exchange(alice_public_key)

if(shared1 == shared2):
    print("sax")