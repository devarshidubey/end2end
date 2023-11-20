import os
import socket
import json
import base64
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

# Function to deserialize X25519 public key from Base64
def deserialize_x25519_key(base64_key):
    serialized_key = base64.b64decode(base64_key)
    public_key = x25519.X25519PublicKey.from_public_bytes(serialized_key)
    return public_key

# Create a socket
server_address = ('localhost', 12345)  # Change this to the address you want to bind
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
    server_socket.bind(server_address)
    server_socket.listen()

    print("Server listening on {}:{}".format(*server_address))

    # Accept connections
    while True:
        client_socket, client_address = server_socket.accept()
        with client_socket:
            print("Accepted connection from", client_address)

            # Receive data from the client
            data = client_socket.recv(1024).decode('utf-8')

            # Parse JSON data
            try:
                data_structure = json.loads(data)

                # Extract UUID from the data structure
                uuid = data_structure.get("uuid")
                if not uuid:
                    print("Error: UUID not provided in JSON data.")
                    continue

                # Create a folder for the UUID if it doesn't exist
                storage_folder = os.path.join(os.getcwd(), uuid)
                os.makedirs(storage_folder, exist_ok=True)

                # Extract keys from the data structure
                keys = data_structure.get("keys", [])

                # Deserialize and store the keys
                for index, base64_key in enumerate(keys):
                    public_key = deserialize_x25519_key(base64_key)

                    # Save the key to a file within the UUID folder
                    filename = os.path.join(storage_folder, f'key_{index + 1}.txt')
                    with open(filename, 'wb') as key_file:
                        key_file.write(public_key.public_bytes(
                            encoding=serialization.Encoding.Raw,
                            format=serialization.PublicFormat.Raw
                        ))

                # Print or process the stored keys
                print(f"Stored Keys for UUID {uuid}:")
                for key_file in os.listdir(storage_folder):
                    with open(os.path.join(storage_folder, key_file), 'rb') as key_file:
                        key_bytes = key_file.read()
                        public_key = x25519.X25519PublicKey.from_public_bytes(key_bytes)
                        print(public_key.public_bytes(
                            encoding=serialization.Encoding.Raw,
                            format=serialization.PublicFormat.Raw
                        ).hex())

            except json.JSONDecodeError as e:
                print("Error decoding JSON:", e)

            # You can add additional logic for sending responses to the client if needed
