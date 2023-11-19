import socket
from cryptography.hazmat.primitives import serialization
import dh
from cryptography.hazmat.backends import default_backend

def load_private_key_from_file(filename='server_private_key.pem'):
    with open(filename, 'rb') as file:
        private_key_bytes = file.read()
        private_key = serialization.load_pem_private_key(
            private_key_bytes,
            password=None,
            backend=default_backend()
        )
    return private_key

def receive_private_key(server_port=12345):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', server_port))
    server_socket.listen(1)

    print("Server listening on port {}".format(server_port))

    connection, client_address = server_socket.accept()
    received_data = connection.recv(4096)
    connection.close()

    return received_data

def save_private_key_to_file(private_key_bytes, filename='server_private_key.pem'):
    with open(filename, 'wb') as file:
        file.write(private_key_bytes)

if __name__ == "__main__":
    received_private_key = receive_private_key()
    save_private_key_to_file(received_private_key)

    server_private_key = load_private_key_from_file()
    server_private_key_for_exchange = dh.X25519PrivateKey.generate()
    server_public_key_for_exchange = server_private_key_for_exchange.public_key()
    shared_key = server_private_key.exchange(server_public_key_for_exchange)

    print(dh.binascii.hexlify(shared_key).decode('utf-8'))

    print("Private key received and saved to file.")
