
import sys
import traceback

import zlib
import protocol
import encryption
import socket
import struct
import binascii
import os


import struct

class Server():
    def __init__(self):
        self.symmetric_key = None
        self.version = 24
        self.client_uuid = None
        self.iv = b'0000000000000000'
        self.clients = []

    def send_packet(self, connection, version, code, *payload_args):
        try:
            # Convert payload arguments to bytes
            payload_args_bytes = []
            total_payload_size = 0
            
            for arg in payload_args:
                arg_bytes = None
                if isinstance(arg, str):
                    arg_bytes = arg.encode()
                    payload_args_bytes.append(arg_bytes)
                    print(f"String Argument: {arg}, Position: {total_payload_size}, Size: {len(arg_bytes)} bytes")
                elif isinstance(arg, int):
                    arg_bytes = struct.pack('<I', arg)  # Convert integer to 4-byte little-endian bytes
                    payload_args_bytes.append(arg_bytes)
                    print(f"Integer Argument: {arg_bytes}, Position: {total_payload_size}, Size: {len(arg_bytes)} bytes")
                else:
                    payload_args_bytes.append(arg)

                if arg_bytes:
                    total_payload_size += len(arg_bytes)

            payload = b"".join(payload_args_bytes)
            header = struct.pack('<BHI', version, code, len(payload))  # < denotes little-endian byte order

            packet = header + payload
            
            print("Sending packet...")
            print("Header:", header)
            print("Payload:", payload)
            print("Payload:", len(payload))
            
            connection.sendall(packet)
            
            print("Packet sent successfully.")
        except Exception as e:
            print("Error sending packet:", e)


    def compute_checksum(self,data):
        print("Input data:", data)
        checksum = zlib.crc32(data) & 0xFFFFFFFF
        print("Computed checksum:", checksum)
        return checksum


    def read_port(self,file_path) -> int:
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

    def generate_uuid(self):
        print('generating uuid')
        return os.urandom(16)


    def check_client_name(self,name: str , client_list):
        signup_validity = True
        for client in client_list:
            if str(client).strip() == name.strip():
                signup_validity = False
                break

        return signup_validity


    def generate_aes_key(self):
        aes_key = encryption.get_random_bytes(32)
        return aes_key

    def zero_pad_string(self,input_string, length):
        if len(input_string) >= length:
            return input_string
        padded_string = input_string.ljust(length, '0')
        return padded_string
    
    def get_all_clients(self,filename = 'clients'):
        clients = []

        try:
            with open(filename, 'r') as file:
                # Read each line from the file
                for line in file:
                    # Extract the username from the line (assuming each line contains only the username)
                    username = line.strip()  # Remove leading/trailing whitespace
                    clients.append(username)
        except FileNotFoundError:
            print("Error: Unable to open file", filename)
        
        return clients
    
    def insert_username(self, username,filename = 'clients'):
        # Open the file in append mode
        with open(filename, 'a') as file:
            # Write the username to the file
            file.write(username + '\n')
        


if __name__ == "__main__":
    try:
        
        server = Server()
        server.clients = server.get_all_clients()
        # 1. read the port from 'port.info'
        port = server.read_port('port.info')
        print(f'waiting in port {port}')
        # 2. check 'clients', if exists load clients that were registered

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
                print(client_id)
                print(version)
                print(request_code)
                print(payload_size)

                # 4. given a request decrypt the request according to the protocol
                payload_data = b''
                while len(payload_data) < payload_size:
                    data = connection.recv(min(1024, payload_size - len(payload_data)))
                    if not data:
                        break
                    payload_data += data
                

                
                
                if request_code == 1025:
                    name = payload_data[:255]
                    name = name.rstrip(b'\x00').decode('utf-8')  

                    signup_response = server.check_client_name(name, server.clients)
                    print('got')
                    if signup_response:
                        RESPONSE_CODE = 1600
                        uuid = server.generate_uuid()
                        server.client_uuid = uuid
                        server.insert_username(name)

                        server.send_packet(connection, version, RESPONSE_CODE, uuid)
                    else:
                        RESPONSE_CODE = 1601
                        server.send_packet(connection,version,RESPONSE_CODE)
                        print('didnt add client')

                
                # public key and name
                elif request_code == 1026:
                    RESPONSE_CODE = 1602
                    name, public_key = payload_data[:255], payload_data[255:415]
                    name = name.rstrip(b'\x00').decode('utf-8')  # Remove padding and decode
                    symmetric_key = server.generate_aes_key()
                    server.symmetric_key = symmetric_key

                    encrypted_key = encryption.rsa_encrypt(symmetric_key, public_key)
                    print('encrypted_key:', encrypted_key)
                    

                    server.send_packet(connection, version, RESPONSE_CODE, server.client_uuid, encrypted_key)
                    
                elif request_code == 1027:
                    name = payload_data[:255]
                    name = name.rstrip(b'\x00').decode('utf-8')  # Remove padding and decode
                    if not server.check_client_name(name,server.clients):
                        pass




                elif request_code == 1028:
                    RESPONSE_CODE = 1603

                    content_size = struct.unpack('<I', payload_data[:4])[0]
                    # # Unpack original file size (4 bytes, little-endian)
                    original_file_size = struct.unpack('<I', payload_data[4:8])[0]

                    # # Unpack packet number and total packets (2 bytes each, little-endian)
                    packet_number, total_packets = struct.unpack('<HH', payload_data[8:12])

                    # # Decode file name (255 bytes)
                    file_name = payload_data[12:267]
                    # # Extract message content
                    message_content = payload_data[267:]

                    try:
                        dec = encryption.decrypt_message(server.symmetric_key,message_content)
                        print('decrypted: ',dec)

                    except:
                        print('something went wrong')
                    
                    try:
                        checksum = server.compute_checksum(message_content)                       
                        print(checksum)
                    except:
                        print('something went wrong')
                    print('connection: ',connection)
                    print('server.version: ',server.version)
                    print('RESPONSE_CODE: ',RESPONSE_CODE)
                    print('server.client_uuid: ',server.client_uuid)
                    print('content_size: ',content_size)
                    print('file_name: ',file_name)
                    print('checksum: ',checksum)
                    try:
                        server.send_packet(connection,server.version,RESPONSE_CODE,server.client_uuid,content_size,file_name,checksum)
                    except:
                        print('sent')







                    # print('encrypted: ',enc)
                    # server.send_packet(connection,server.version,RESPONSE_CODE,message)

                elif request_code == 1029:
                    pass
                elif request_code == 1030:
                    pass
                elif request_code == 1031:
                    pass
    except Exception as e:
        print(f"Closing the program")
        receiver_socket.close()
