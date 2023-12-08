import socket
import threading
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import base64
import json, os
import binascii
exit_event = threading.Event()

def derive_aes_key(shared_secret):
    # Using HKDF with SHA-256 as the hash function
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # 32 bytes = 256 bits
        salt=None,  # No salt for simplicity, adjust as needed
        info=b'AES Key Derivation',  # Additional context information
        backend=default_backend()
    )

    # Derive the key
    aes_key = hkdf.derive(shared_secret)

    return aes_key

def encrypt(message, key):
    # Create an AES-ECB cipher with the provided key
    plaintext = message.encode('utf-8')
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()

    # Pad the plaintext to be a multiple of the block size
    block_size = algorithms.AES.block_size // 8
    plaintext_padded = plaintext + b'\x00' * (block_size - len(plaintext) % block_size)

    # Encrypt the padded plaintext
    ciphertext = encryptor.update(plaintext_padded) + encryptor.finalize()

    return ciphertext

def decrypt(ciphertext, key):
    # Create an AES-ECB cipher with the provided key
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the ciphertext
    plaintext_padded = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove padding from the decrypted plaintext
    plaintext = plaintext_padded.rstrip(b'\x00')

    return plaintext

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

def deserialize_x25519_key(base64_key):
    serialized_key = base64.b64decode(base64_key)
    public_key = x25519.X25519PublicKey.from_public_bytes(serialized_key)
    return public_key

def publish_key_bundle(uuid, public_key1, public_key2, public_key3):
    base64_key1 = serialize_x25519_key(public_key1)
    base64_key2 = serialize_x25519_key(public_key2)
    base64_key3 = serialize_x25519_key(public_key3)

    data_structure = {
        "request_type":"upload_prekey_bundle",
        "keys": [base64_key1, base64_key2, base64_key3],
        "uuid": uuid
    }

    json_data = json.dumps(data_structure)
    server_address = ('localhost', 12345) 
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(server_address)    
        s.sendall(json_data.encode('utf-8'))
        s.close()

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
        publish_key_bundle("bob", public_keys[0], public_keys[1], public_keys[2])

def fetch_prebundle_keys(uuid):
    data_structure = {
        "request_type":"fetch_prebundle_keys",
        "keys": [],
        "uuid": uuid
    }

    json_data = json.dumps(data_structure)
    server_address = ('localhost', 12345) 
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(server_address) 
        s.sendall(json_data.encode('utf-8'))

        data = s.recv(1024).decode('utf-8')

        try: 
            if data:
                data_structure = json.loads(data)
                keys = data_structure.get("keys", [])
                key_list = []
                print("Received key bundles:")
                for index, base64_key in enumerate(keys):
                    public_key =  deserialize_x25519_key(base64_key)
                    key_list.append(public_key)
                    print(public_key.public_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PublicFormat.Raw
                        ).hex()
                    )
        except:
            print("failed to load json 2")

def recieve_init_message():

    data_structure = {
        "request_type":"recv_init_message",
        "uuid": "bob",
    }

    json_data = json.dumps(data_structure)
    server_address = ('localhost', 12345) 

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(server_address)    
        s.sendall(json_data.encode('utf-8'))

        data = s.recv(1024).decode('utf-8')

        try: 
            if data:
                data_structure = json.loads(data)
                keys = data_structure.get("keys", [])
                key_list = []
                for index, base64_key in enumerate(keys):
                    public_key =  deserialize_x25519_key(base64_key)
                    key_list.append(public_key)
            return key_list
        except:
            print("failed to load json 2")
def read_local_private_keys():
    keys = []
    for key_file in os.listdir("private_keys"):
        with open(os.path.join("private_keys", key_file), 'rb') as key_file:
            key_bytes = key_file.read()
            public_key = x25519.X25519PrivateKey.from_private_bytes(key_bytes)
            keys.append(public_key)
    return keys

def create_shared_secret(alice_key_list):
    bob_keys = read_local_private_keys()
    dh1 = bob_keys[1].exchange(alice_key_list[0])
    dh2 = bob_keys[0].exchange(alice_key_list[1])
    dh3 = bob_keys[1].exchange(alice_key_list[1])
    dh4 = bob_keys[2].exchange(alice_key_list[1])
    shared_secret = dh1+dh2+dh3+dh4
    hex_representation = binascii.hexlify(shared_secret).decode('utf-8')
    
    # print("shared secret: ", hex_representation)
    return shared_secret 

def send_messages(s):
    while not exit_event.is_set():
        try:
            message = input("Enter message to send (or 'close' to quit): \n")
            if message.lower() == 'close':
                exit_event.set()
                s.sendall(message.encode('utf-8'))
                continue
            key = read_byte_object_from_file('aes_key')
            
            ciphertext = encrypt(message, key)
            print(ciphertext)
            s.sendall(ciphertext)
            print(f"Sent: {message}")
        except Exception as e:
            # print(f"Error sending data: {e}")
            print(f"Error sending data",e)
            break

def receive_messages(s):
    while not exit_event.is_set():
        try:
            data = s.recv(1024)
            if not data:
                break
            received_message = data
            key = read_byte_object_from_file('aes_key')
            decrypted_text = decrypt(received_message, key).decode('utf-8')
            print(f"Received: {decrypted_text}\n")
        except socket.error as e:
            # Handle the exception (e.g., print an error message)
            print(f"Error receiving data: {e}")
            break

def msg_functionality(s):
    try:
        data_structure = {
        "request_type":"msg-bob",
        "uuid": "bob",
         }
        json_data = json.dumps(data_structure)
        s.sendall(json_data.encode('utf-8'))

        # Create threads for sending and receiving messages
        send_thread = threading.Thread(target=send_messages, args=(s,))
        receive_thread = threading.Thread(target=receive_messages, args=(s,))

        # Start the threads
        send_thread.start()
        receive_thread.start()

        send_thread.join()
        receive_thread.join()

    except Exception as e:
        print(f"Message functionality failed: {e}")   

    while not exit_event.is_set():
        return
    
def save_byte_object_to_file(byte_object, file_name):
    file_path = os.path.join(os.path.dirname(__file__), file_name)
    with open(file_path, 'wb') as file:
        file.write(byte_object)

def read_byte_object_from_file(file_name):
    file_path = os.path.join(os.path.dirname(__file__), file_name)
    with open(file_path, 'rb') as file:
        byte_object = file.read()
    return byte_object

if __name__ == "__main__":
    server_address = ('localhost', 12345) 
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(server_address)    
        # install_app()
        # print("INSTALL APP FINISHED")
        # # fetch_prebundle_keys("alice")

        # alice_keys = recieve_init_message()
        # shared_secret = create_shared_secret(alice_keys)
        # aes_key = derive_aes_key(shared_secret)
        # save_byte_object_to_file(aes_key, 'aes_key')
        # print("aes key:",binascii.hexlify(aes_key).decode('utf-8'))

        # alice_keys = recieve_init_message()
        # create_shared_secret(alice_keys)
        msg_functionality(s)
#NOTE TO SELF: 1. THE INSTALLATION FILE WILL CONTAIN DATE OF INSTALLATION, INFO ABOUT LAST TIME THE SIGNED PREKEY WAS UPDATED
#2. BEFORE PUBLISHING THE KEYS DURING INSTALLATION, THE CLIENT MUST ASK THE SERVER TO RESERVE A UUID FOR ITSELF. THE SERVER WILL MAP THE UUID WITH THE IP ADDRESS(OR MAC ADDRESS) OF THE CLIENT, THE CLIENT WILL THEN STORE THAT UUID IN LOCAL MACHINE
#3 UPLOAD THE SIGNATURE OF THE SIGNED PREKEY, SIGNED WITH IDENTITY KEY