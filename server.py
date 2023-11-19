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
        #very very imp
        public_key = serialization.load_pem_public_key(data, default_backend()) #very imp
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
