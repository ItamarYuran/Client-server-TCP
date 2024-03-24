
import sys
import traceback


import protocol
import encryption
import socket
import struct
import os



def read_port(file_path) -> int:
    port = 1256  # default port
    try:
        with open(file_path, 'r') as file:
            file_contents = file.read().strip()  # Remove any leading/trailing whitespace
            try:
                port = int(file_contents)
                if 1 <= port <= 65535:
                    return port
                else:
                    print("Error: Port number out of valid range (1-65535). Using default port.")
            except ValueError:
                print("Error: Invalid port number format in the file. Using default port.")
    except FileNotFoundError:
        print(f"Warning: The file '{file_path}' does not exist.")
    except Exception as e:
        print(f"An error occurred: {e}")
    return port

def generate_uuid():
    return os.urandom(16)


def check_client_name(name: str , client_list):
    signup_validity = True
    for client in client_list:
        if client['name'] == name:
            signup_validity = False
            break
    return signup_validity



def read_client_list(file_path='clients'):
    data_list = []  
    try:
        with open(file_path, 'r') as file:
            for line in file:
                line = line.strip()  
                if not line:
                    continue  # Skip empty lines

                parts = line.split(':')
                if len(parts) < 2:
                    continue  # Skip invalid lines

                # Extract the first three parts as ID, Name, and password_hash
                ID, Name, password_hash = parts[:3]

                # Concatenate the remaining parts as the last_seen field
                last_seen = ":".join(parts[3:])

                # Create a dictionary with the extracted information
                data_dict = {
                    'client_id': ID,
                    'name': Name,
                    'password_hash': password_hash,
                    'last_seen': last_seen,
                }
                data_list.append(data_dict)

    except FileNotFoundError:
        print(f"Warning: The file '{file_path}' does not exist.")
    except Exception as e:
        print(f"An error occurred: {e}")

    return data_list




def get_name_and_pass_hash(uuid, file_path='clients'):
    # Read the file
    with open(file_path, 'r') as file:
        lines = file.readlines()

    # Iterate over the lines to find the UUID
    for line in lines:
        fields = line.strip().split(':')
        if len(fields) == 4 and fields[0] == uuid:
            name = fields[1]
            pass_hash = fields[2]
            return name, pass_hash

    # If the UUID is not found, return None
    return None, None


def generate_encrypted_key(client_symmetric_key, nonce):
    # Generate AES key (32 bytes)
    aes_key = encryption.get_random_bytes(32)
    encrypted_key_iv = encryption.get_random_bytes(16)

    # Encrypt nonce with the client's symmetric key using AES in CBC mode
    encrypted_nonce = encryption.encrypt_message(client_symmetric_key, encrypted_key_iv, nonce)
    encrypted_aes_key = encryption.encrypt_message(client_symmetric_key, encrypted_key_iv, aes_key)

    encrypted_key = {
        'encrypted_key_iv': encrypted_key_iv,
        'nonce': encrypted_nonce,
        'aes_key': encrypted_aes_key
    }
    return encrypted_key, aes_key


def add_client(client_id, name, hashed_password, timestamp, file_path='clients'):
    with open(file_path, 'a') as file:
        # Create the formatted string with the provided information
        entry = f"{client_id}:{name}:{hashed_password}:{timestamp}\n"
        file.write(entry)


if __name__ == "__main__":
    try:
        # 1. read the port from 'port.info'
        port = read_port('port.info')
        print(f'waiting in port {port}')
        # 2. check 'clients', if exists load clients that were registered
        client_list = read_client_list()

        # 3. wait for requests from clients
        # Create a socket
        receiver_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        receiver_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        receiver_socket.bind(('localhost', port))  # Bind to a local address and port
        receiver_socket.listen(1)  # Listen for incoming connections

        while True:
            # Listener
            try:
                connection, client_address = receiver_socket.accept()
                print(f'new connection from address {client_address}')
            except KeyboardInterrupt:
                raise Exception

            while True:

                header_format = '<16sBHI'
                header_size = struct.calcsize(header_format)
                header_data = connection.recv(header_size)
                if not header_data:
                    break

                client_id, version, request_code, payload_size = struct.unpack(header_format, header_data)
                print(f"Received request code: {request_code}")

                # 4. given a request decrypt the request according to the protocol
                payload_data = b''
                while len(payload_data) < payload_size:
                    data = connection.recv(min(4096, payload_size - len(payload_data)))
                    if not data:
                        break
                    payload_data += data

                
                
                if request_code == 1025:
                    name = payload_data[:255]
                    name = name.rstrip(b'\x00').decode('utf-8')  # Remove padding and decode

                    signup_response = check_client_name(name, client_list)
                    if signup_response:
                        RESPONSE_CODE = 1600
                        client_id = generate_uuid()
                        print(f"Client ID: {client_id.hex()}")
                        packet = protocol.create_packet(RESPONSE_CODE, client_id, 'auth', protocol.VERSION, client_id)
                        add_client(client_id.hex(), name)
                    else:
                        RESPONSE_CODE = 1601
                        packet = protocol.create_packet(RESPONSE_CODE, client_id, 'auth', protocol.VERSION)

                    connection.sendall(packet)
                
                # public key and name
                elif request_code == 1026:
                    name, public_key = payload_data[:255],payload_data[255:415]

                # reconnecting request
                elif request_code == 1027:
                    name = payload_data[:255]
                    name = name.rstrip(b'\x00').decode('utf-8')  # Remove padding and decode
                    if not check_client_name(name,client_list):
                        pass




                elif request_code == 1028:
                    pass
                elif request_code == 1029:
                    pass
                elif request_code == 1030:
                    pass
                elif request_code == 1031:
                    pass
    except Exception as e:
        print(f"Closing the program")
        receiver_socket.close()
