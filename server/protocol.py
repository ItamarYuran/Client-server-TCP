
import struct

VERSION = 24
VERSION_BYTES = b'24'


FORMATS = {
    1025: '<255s',  #       signup 
    1026: '<255s160s',  # public key
    1027: '<255s',  # reconnecting
    1028: '<4s4s4s255s',  # file send                           need to change!
    1029: '<255s',  # valid crc
    1030: '<255s',  # invalid crc
    1031: '<255s',  # invalid crc last time

    1600: '<16s',  # successful Registration
    1601: '<',  # Failed Registration
    1602: '<16s',  # got public key sending aes key                          need to change!
    1603: '<16s4s255s4s',  # got a valid file with crc
    1604: '<16s',  # approving recieving
    1605: '<16s',  # approving reconnecting                                     need to change!
    1606: '<16s',  # declined reconnecting
    1607: '<',  # general error
}


HEADER_FORMATS = {
    'client': '<16sBHI',
    'server': '<BHI',
}


def create_packet(code: int, client_id: bytes, role: str, version: int, *args):
    if code in FORMATS:
        payload_format = FORMATS[code]

        print(f"{payload_format=}", debug=True)

        if role == 'client_msg':
            payload_format = f"{payload_format}{len(args[2])}s"

        payload = struct.pack(payload_format, *args)

        # Calculate the payload size
        payload_size = len(payload)

        print(f"Payload: {payload}", debug=True)
        print(f"Payload Size: {payload_size}", debug=True)

        header_format = HEADER_FORMATS[role]

        if type(client_id) == str:
            client_id = client_id.encode('utf-8')

        # Create the header
        if role in {'client', 'client_msg'}:
            header = struct.pack(header_format, client_id, version, code, payload_size)  # header send server
        elif role in {'auth', 'msg'}:
            header = struct.pack(header_format, version, code, payload_size)  # header sent to client

        packet = header + payload
        return packet
    else:
        raise ValueError(f"Unsupported request code: {code}")
