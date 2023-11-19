import socket
from cryptography.hazmat.primitives import serialization
import dh

def send_private_key(private_key, server_ip='127.0.0.1', server_port=12345):
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((server_ip, server_port))
    client_socket.sendall(private_key_bytes)
    client_socket.close()

if __name__ == "__main__":
    private_key, public_key = dh.generate_keys()
    
    send_private_key(private_key)
