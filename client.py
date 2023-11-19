import socket
from cryptography.hazmat.primitives import serialization
import dh

def send_public_key(public_key, server_ip='127.0.0.1', server_port=12345):
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((server_ip, server_port))
    client_socket.sendall(public_key_bytes)
    client_socket.close()

if __name__ == "__main__":
    private_key, public_key = dh.generate_keys()
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    print(public_key_bytes.hex())
    send_public_key(public_key)
