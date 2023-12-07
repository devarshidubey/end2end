import os
import socket
import json
import base64
from queue import Queue
import threading
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
global data_structure1

global alice_queue
global bob_queue

exit_event = threading.Event()
exit_event2 = threading.Event()

alice_queue = Queue()
bob_queue = Queue()

# alice_queue.put("message1")
# alice_queue.put("message2")

# Function to deserialize X25519 public key from Base64
def deserialize_x25519_key(base64_key):
    serialized_key = base64.b64decode(base64_key)
    public_key = x25519.X25519PublicKey.from_public_bytes(serialized_key)
    return public_key

def serialize_x25519_key(public_key):
    serialized_key = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    base64_key = base64.b64encode(serialized_key).decode('utf-8')
    return base64_key

def fetch_prebundle_keys(uuid,client_socket):
    try:
        # Check if the folder for the UUID exists
        storage_folder = os.path.join(os.getcwd(), uuid)
        if not os.path.exists(storage_folder):
            print(f"Error: Folder for UUID {uuid} does not exist.")
            return None  # Return None or appropriate value indicating failure
        
        # Fetch and return the keys
        keys = []
        for key_file in os.listdir(storage_folder):
            with open(os.path.join(storage_folder, key_file), 'rb') as key_file:
                key_bytes = key_file.read()
                public_key = x25519.X25519PublicKey.from_public_bytes(key_bytes)
                keys.append(serialize_x25519_key(public_key))
        
        data_structure = {
            "keys":keys
        }  
        print("**Printing++") 

        json_data = json.dumps(data_structure)

        client_socket.sendall(json_data.encode('utf-8'))           

        # return keys
    except Exception as e:
        print(f"Error: Fetching prekey bundle for UUID {uuid} failed:", e)
        return None  # Return None or appropriate value indicating failure

def upload_prekey_bundle(uuid,data_structure):
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

            # except json.JSONDecodeError as e:
            #     print("Error decoding JSON:", e)

def send_to_bob(client_socket):
    try:
        # Check if the folder for the UUID exists
        data_structure = data_structure1
        print("**Printing++") 

        json_data = json.dumps(data_structure)

        client_socket.sendall(json_data.encode('utf-8'))           

    except Exception as e:
        print(f"Error: Fetching prekey bundle for UUID {uuid} failed:", e)
        return None  # Return None or appropriate value indicating failure

def send_messages2(client_socket):
    print("send message is ready")
    while not exit_event2.is_set():
        # print("send message is sending")
        # Get message from Bob's queue and send it to him
        if not bob_queue.empty():
            message = bob_queue.get()
            client_socket.sendall(message.encode('utf-8'))
            print(f"Sent to Bob: {message}")

def receive_messages2(client_socket):
    try:
        print("receive message is ready")
        while not exit_event2.is_set():
            print("receive message is receiving")      
            data = client_socket.recv(1024)
            if not data:
                print("Connection closed by the client.")
                break
            received_message = data.decode('utf-8')
            if(received_message == "close"):
                exit_event2.set()
                break
            print(f"Received from Alice: {received_message}")

            # Put the received message in Bob's queue
            alice_queue.put(received_message)
            elements = list(alice_queue.queue)
            for element in elements:
                print(element)
    except ConnectionResetError:
        print("ConnectionResetError: Connection closed by the client.")
    finally:
        print("Connection closed by the client.")
        exit_event2.clear()
        # Close the client socket in the 'finally' block
        client_socket.close()


def msg_functionality2(client_socket):
    print("msg f2 working")
    try:
        # Create threads for sending and receiving messages
        send_thread = threading.Thread(target=send_messages2, args=(client_socket,))
        receive_thread = threading.Thread(target=receive_messages2, args=(client_socket,))
        print("threads activated")
        # Start the threads
        send_thread.start()
        receive_thread.start()
        print("threads started")
        send_thread.join()
        receive_thread.join()
        print("threads joined")
    except Exception as e:
        print(f"Message functionality failed: {e}")  
        client_socket.close()

    while not exit_event2.is_set():
        exit_event2.clear()
        return


#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

def send_messages(client_socket):
    # print("send message is ready")
    while not exit_event.is_set():
        # print("send message is sending")
        # Get message from Alice's queue and send it to her
        if not alice_queue.empty():
            message = alice_queue.get()
            client_socket.sendall(message.encode('utf-8'))
            print(f"Sent to Alice: {message}")

def receive_messages(client_socket):
    try:
        # print("receive message is ready")
        while not exit_event.is_set():
            # print("receive message is receiving")      
            data = client_socket.recv(1024)
            if not data:
                print("Connection closed by the client.")
                break
            received_message = data.decode('utf-8')
            if(received_message == "close"):
                exit_event.set()
                break
            print(f"Received from Bob: {received_message}")

            # Put the received message in Bob's queue
            bob_queue.put(received_message)
            elements = list(bob_queue.queue)
            for element in elements:
                print(element)
    except ConnectionResetError:
        print("ConnectionResetError: Connection closed by the client.")
    finally:
        print("Connection closed by the client.")
        exit_event.clear()
        # Close the client socket in the 'finally' block
        client_socket.close()


def msg_functionality(client_socket):

    try:
        # Create threads for sending and receiving messages
        send_thread = threading.Thread(target=send_messages, args=(client_socket,))
        receive_thread = threading.Thread(target=receive_messages, args=(client_socket,))
        # print("threads activated")
        # Start the threads
        send_thread.start()
        receive_thread.start()
        # print("threads started")
        send_thread.join()
        receive_thread.join()
        # print("threads joined")
    except Exception as e:
        print(f"Message functionality failed: {e}")  
        client_socket.close()

    while not exit_event.is_set():
        exit_event.clear()
        return    


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
            data_structure=None
            # Parse JSON data
            try:
                data_structure = json.loads(data)
            except json.JSONDecodeError as e:
                print("Error: Loading Json Data failed:", e)   

            # Extract UUID from the data structure
            uuid = data_structure.get("uuid")
            if not uuid:
                print("Error: UUID not provided in JSON data.")
                continue
                
            if data_structure is not None:
                if data_structure["request_type"] == "upload_prekey_bundle":
                    upload_prekey_bundle(uuid,data_structure)
                elif data_structure["request_type"] == 'fetch_prebundle_keys':
                    fetch_prebundle_keys(data_structure["uuid"],client_socket)   
                elif data_structure["request_type"] == 'init_message':
                    print(data_structure)
                    data_structure1 = data_structure
                elif data_structure["request_type"] == 'recv_init_message':  
                    send_to_bob(client_socket)
                elif data_structure["request_type"] == 'msg-alice':  
                    msg_functionality(client_socket)    
                elif data_structure["request_type"] == 'msg-bob':  
                    msg_functionality2(client_socket)                      
                # Create a folder for the UUID if it doesn't exist
            #     storage_folder = os.path.join(os.getcwd(), uuid)
            #     os.makedirs(storage_folder, exist_ok=True)

            #     # Extract keys from the data structure
            #     keys = data_structure.get("keys", [])

            #     # Deserialize and store the keys
            #     for index, base64_key in enumerate(keys):
            #         public_key = deserialize_x25519_key(base64_key)

            #         # Save the key to a file within the UUID folder
            #         filename = os.path.join(storage_folder, f'key_{index + 1}.txt')
            #         with open(filename, 'wb') as key_file:
            #             key_file.write(public_key.public_bytes(
            #                 encoding=serialization.Encoding.Raw,
            #                 format=serialization.PublicFormat.Raw
            #             ))

            #     # Print or process the stored keys
            #     print(f"Stored Keys for UUID {uuid}:")
            #     for key_file in os.listdir(storage_folder):
            #         with open(os.path.join(storage_folder, key_file), 'rb') as key_file:
            #             key_bytes = key_file.read()
            #             public_key = x25519.X25519PublicKey.from_public_bytes(key_bytes)
            #             print(public_key.public_bytes(
            #                 encoding=serialization.Encoding.Raw,
            #                 format=serialization.PublicFormat.Raw
            #             ).hex())

            # except json.JSONDecodeError as e:
            #     print("Error decoding JSON:", e)

            # You can add additional logic for sending responses to the client if needed
