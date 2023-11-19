# from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives import serialization
# from cryptography.hazmat.primitives.asymmetric import x25519
# import socket

# def load_private_key_from_file(filename='server_private_key.pem'):
#     with open(filename, 'rb') as file:
#         private_key_bytes = file.read()
#         private_key = serialization.load_pem_private_key(
#             private_key_bytes,
#             password=None,
#             backend=default_backend()
#         )
#     return private_key

# def perform_key_exchange(private_key, other_public_key):
#     shared_key = private_key.exchange(other_public_key)
#     return shared_key

# def start_server(server_port=12345):
#     server_private_key = load_private_key_from_file()

#     server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     server_socket.bind(('0.0.0.0', server_port))
#     server_socket.listen(1)

#     print("Server listening on port {}".format(server_port))

#     while True:
#         connection, client_address = server_socket.accept()
        
#         # Receive the public key in chunks until the entire key is received
#         received_public_key_bytes = b""
#         while len(received_public_key_bytes) < 32:
#             chunk = connection.recv(32 - len(received_public_key_bytes))
#             if not chunk:
#                 break
#             received_public_key_bytes += chunk

#         # Convert the received public key bytes to a public key object
#         received_public_key = x25519.X25519PublicKey.from_public_bytes(received_public_key_bytes)
#         print(received_public_key_bytes.hex())
#         # Perform key exchange
#         shared_key = perform_key_exchange(server_private_key, received_public_key)

#         print("Shared Key:", shared_key.hex())

#         connection.close()

# if __name__ == "__main__":
#     start_server()

import socket
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.backends import default_backend

def receive_public_key():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('127.0.0.1', 12345))
    server_socket.listen(1)

    print("Waiting for a connection...")
    connection, address = server_socket.accept()
    print(f"Connection from {address}")
    
    with connection:
        data = connection.recv(4096)
        public_key = serialization.load_pem_public_key(data, default_backend())
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        print(public_key_bytes.hex())
        return public_key

def perform_dh_exchange(private_key, public_key):
    shared_key = private_key.exchange(public_key)
    return shared_key

if __name__ == "__main__":
    # Load server private key from file
    with open('server_private_key.pem', 'rb') as key_file:
        private_key_data = key_file.read()
        private_key = serialization.load_pem_private_key(
            private_key_data,
            password=None,
            backend=default_backend()
        )

    # Receive public key from the client
    client_public_key = receive_public_key()

    # Perform X25519 DH exchange
    shared_key = perform_dh_exchange(private_key, client_public_key)

    print(f"Shared Key: {shared_key.hex()}")
