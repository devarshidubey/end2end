import socket
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
import base64
import json, os

def generate_x25519_key():
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    print(public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    ).hex())
    return private_key, public_key

def serialize_x25519_key(public_key):
    serialized_key = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    base64_key = base64.b64encode(serialized_key).decode('utf-8')
    return base64_key

def publish_key_bundle(uuid, public_key1, public_key2, public_key3):
    base64_key1 = serialize_x25519_key(public_key1)
    base64_key2 = serialize_x25519_key(public_key2)
    base64_key3 = serialize_x25519_key(public_key3)

    data_structure = {
        "keys": [base64_key1, base64_key2, base64_key3],
        "uuid": uuid
    }

    json_data = json.dumps(data_structure)

    server_address = ('localhost', 12345)  # Change this to your server's address
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(server_address)

        s.sendall(json_data.encode('utf-8'))

def store_local_keys():
    storage_folder = os.path.join(os.getcwd(), "public_keys")
    storage_folder2 = os.path.join(os.getcwd(), "private_keys")
    os.makedirs(storage_folder, exist_ok=True)
    os.makedirs(storage_folder2, exist_ok=True)
    filenames1 = [
            '1identity_public',
            '2signed_public',
            '3one_time_public'
                    ]
    filenames2 = [
            '1identity_private',
            '2signed_private',
            '3one_time_private'
                    ]
    for i in range(3):
        filename = os.path.join(storage_folder, f'{filenames1[i]}.txt')
        filename1 = os.path.join(storage_folder2, f'{filenames2[i]}.txt')
        private_key, public_key = generate_x25519_key()

        with open(filename, 'wb') as key_file:
            key_file.write(public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            ))
        with open(filename1, 'wb') as key_file:
            key_file.write(private_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            ))

def read_local_keys():
    keys = []
    for key_file in os.listdir("public_keys"):
        with open(os.path.join("public_keys", key_file), 'rb') as key_file:
            key_bytes = key_file.read()
            public_key = x25519.X25519PublicKey.from_public_bytes(key_bytes)
            keys.append(public_key)
    return keys

def install_app():
    if not os.path.isfile("installation"):
        store_local_keys()
        public_keys = read_local_keys()

        with open("installation", "w") as installation_file:
            installation_file.write("Installation file created.\n")
        publish_key_bundle("uuid25519", public_keys[0], public_keys[1], public_keys[2])

if __name__ == "__main__":
    install_app()

#NOTE TO SELF: 1. THE INSTALLATION FILE WILL CONTAIN DATE OF INSTALLATION, INFO ABOUT LAST TIME THE SIGNED PREKEY WAS UPDATED
#2. BEFORE PUBLISHING THE KEYS DURING INSTALLATION, THE CLIENT MUST ASK THE SERVER TO RESERVE A UUID FOR ITSELF. THE SERVER WILL MAP THE UUID WITH THE IP ADDRESS(OR MAC ADDRESS) OF THE CLIENT, THE CLIENT WILL THEN STORE THAT UUID IN LOCAL MACHINE
#3 UPLOAD THE SIGNATURE OF THE SIGNED PREKEY, SIGNED WITH IDENTITY KEY