import socket
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
import base64
import json

# Function to generate X25519 public key
def generate_x25519_key():
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    print(public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    ).hex())
    return private_key, public_key

# Function to serialize X25519 public key to Base64
def serialize_x25519_key(public_key):
    serialized_key = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    base64_key = base64.b64encode(serialized_key).decode('utf-8')
    return base64_key

def publish_key_bundle(uuid, public_key1, public_key2, public_key3):
    # Serialize X25519 public keys to Base64
    base64_key1 = serialize_x25519_key(public_key1)
    base64_key2 = serialize_x25519_key(public_key2)
    base64_key3 = serialize_x25519_key(public_key3)

    # Define the data structure
    data_structure = {
        "keys": [base64_key1, base64_key2, base64_key3],
        "uuid": uuid
        # You can include other information in the data structure as needed
    }

    # Convert data structure to JSON
    json_data = json.dumps(data_structure)

    # Connect to the server
    server_address = ('localhost', 12345)  # Change this to your server's address
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(server_address)

        # Send the JSON data
        s.sendall(json_data.encode('utf-8'))

        # You can add additional logic for receiving responses from the server if needed

    # Note: This is a basic example and does not include error handling or encryption.
    # In a production scenario, you should consider using TLS/SSL for secure communication.

# Create three X25519 key pairs
private_key1, public_key1 = generate_x25519_key()
private_key2, public_key2 = generate_x25519_key()
private_key3, public_key3 = generate_x25519_key()

publish_key_bundle("uuid25519", public_key1, public_key2, public_key3)