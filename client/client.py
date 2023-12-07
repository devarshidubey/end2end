import socket
import threading
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
import base64
import json, os
import binascii
exit_event = threading.Event()

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

def read_local_private_keys():
    keys = []
    for key_file in os.listdir("private_keys"):
        with open(os.path.join("private_keys", key_file), 'rb') as key_file:
            key_bytes = key_file.read()
            public_key = x25519.X25519PrivateKey.from_private_bytes(key_bytes)
            keys.append(public_key)
    return keys

def install_app():
    if not os.path.isfile("installation"):
        store_local_keys()
        public_keys = read_local_keys()
        with open("installation", "w") as installation_file:
            installation_file.write("Installation file created.\n")
        publish_key_bundle("alice", public_keys[0], public_keys[1], public_keys[2])

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
                # print("Received key bundles:")
                for index, base64_key in enumerate(keys):
                    public_key =  deserialize_x25519_key(base64_key)
                    key_list.append(public_key)
            return key_list
        except:
            print("failed to load json 2")

def create_shared_secret(bob_key_list):
    alice_keys = read_local_private_keys()
    ephemeral_key_pri, ephemeral_key_pub = generate_x25519_key()
    dh1 = alice_keys[0].exchange(bob_key_list[1])
    dh2 = ephemeral_key_pri.exchange(bob_key_list[0])
    dh3 = ephemeral_key_pri.exchange(bob_key_list[1])
    dh4 = ephemeral_key_pri.exchange(bob_key_list[2])
    shared_secret = dh1+dh2+dh3+dh4
    hex_representation = binascii.hexlify(shared_secret).decode('utf-8')
    
    print("shared secret: ", hex_representation)
    return ephemeral_key_pub, shared_secret

def send_initial_message(ephemeral_pub):
    msg = "This connection is now end-to-end encrypted"
    alice_pub_key = read_local_keys()[0]
    base64_key_id = serialize_x25519_key(alice_pub_key)
    base64_key_eph = serialize_x25519_key(ephemeral_pub)
    
    keys = [base64_key_id, base64_key_eph]
    data_structure = {
        "request_type":"init_message",
        "keys": keys,
        "uuid": "bob",
        "msg": msg
    }
    # print(keys)

    json_data = json.dumps(data_structure)
    server_address = ('localhost', 12345) 
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(server_address)    
        s.sendall(json_data.encode('utf-8'))
        s.close()

def send_messages(s):
    while not exit_event.is_set():
        try:
            message = input("Enter message to send (or 'close' to quit): \n")
            if message.lower() == 'close':
                exit_event.set()

            s.sendall(message.encode('utf-8'))
            print(f"Sent: {message}")
        except Exception as e:
            # print(f"Error sending data: {e}")
            print(f"Error sending data")
            break

def receive_messages(s):
    while not exit_event.is_set():
        try:
            data = s.recv(1024)
            if not data:
                break
            received_message = data.decode('utf-8')
            print(f"Received: {received_message}\n")
        except socket.error as e:
            # Handle the exception (e.g., print an error message)
            print(f"Error receiving data: {e}")
            break

def msg_functionality(s):
    try:
        data_structure = {
        "request_type":"msg-alice",
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
    
if __name__ == "__main__":
    server_address = ('localhost', 12345) 
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(server_address)    
        print("Connection established successfully.")

        # install_app()
        # print("INSTALL APP FINISHED")
        # bob_key_list = fetch_prebundle_keys("bob")

        # ephemeral_key_pub, shared_secret = create_shared_secret(bob_key_list)

        # send_initial_message(ephemeral_key_pub)

        msg_functionality(s)

#NOTE TO SELF: 1. THE INSTALLATION FILE WILL CONTAIN DATE OF INSTALLATION, INFO ABOUT LAST TIME THE SIGNED PREKEY WAS UPDATED
#2. BEFORE PUBLISHING THE KEYS DURING INSTALLATION, THE CLIENT MUST ASK THE SERVER TO RESERVE A UUID FOR ITSELF. THE SERVER WILL MAP THE UUID WITH THE IP ADDRESS(OR MAC ADDRESS) OF THE CLIENT, THE CLIENT WILL THEN STORE THAT UUID IN LOCAL MACHINE
#3 UPLOAD THE SIGNATURE OF THE SIGNED PREKEY, SIGNED WITH IDENTITY KEY