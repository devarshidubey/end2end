import dh
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

server = []
class Bundle:
    def __init__(self, dict):
        self.uuid = dict["uuid"]
        self.identity_key = dict["identity_key"]
        self.signed_prekey = dict["signed_prekey"]
        self.signature = dict["signature"]
        self.one_time_prekeys = dict["one_time_prekeys"]
    
        

def retrievePreKeyBundle(uuid):
    for bundle in server:
        if bundle.uuid == uuid:
            return bundle

bob_identity_private, bob_identity_public = dh.generate_keys()
bob_ephemeral_private, bob_ephemeral_public = dh.generate_keys()
bob_signed_prekey_private, bob_signed_prekey_public = dh.generate_keys()
bob_one_time_public_keys = []
bob_one_time_private_keys = []
for i in range(10):
    private, public = dh.generate_keys()
    bob_one_time_public_keys.append(public)
    bob_one_time_private_keys.append(private)



alice_identity_private, alice_identity_public = dh.generate_keys()
alice_signed_prekey_private, alice_signed_prekey_public = dh.generate_keys()


