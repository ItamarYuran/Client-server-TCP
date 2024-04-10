import rsa
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import struct
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.number import bytes_to_long
import base64
import binascii


def rsa_encrypt(plaintext, public_key_bytes):
    try:
        public_key = RSA.import_key(public_key_bytes)
        cipher = PKCS1_OAEP.new(public_key)
        ciphertext = cipher.encrypt(plaintext)
        encrypted_base64 = base64.b64encode(ciphertext)

        return encrypted_base64.decode()
    except Exception as e:
        print("Error occurred during encryption:", e)
        return None



def random_bytes(length):
    return get_random_bytes(length)

def pad_data(data):
    # Pad the data using PKCS#7 padding scheme
    padded_data = pad(data, AES.block_size)
    return padded_data

def generate_rsa_keypair():
    return rsa.newkeys(2048)  # Generate a new RSA key pair with 2048-bit key size


def rsa_decrypt(encrypted_message, private_key):
    decrypted_message = rsa.decrypt(encrypted_message, private_key)
    return decrypted_message

# Encrypt a message using AES-CBC
def encrypt_message(key, iv, message):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad_data(message.encode('utf-8'))
    ciphertext = cipher.encrypt(padded_message)
    return ciphertext

def decrypt_message(key, ciphertext):
    try:
        iv = bytes([0] * AES.block_size)
        ciphertext_bytes = binascii.unhexlify(ciphertext)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = cipher.decrypt(ciphertext_bytes)
        unpadded_message = unpad(decrypted_data, AES.block_size)
        return unpadded_message

    except ValueError as e:
        print("Decryption error:", e)
        return None


    
if __name__ == "__main__":
    iv = bytes(16)
    aes_key = random_bytes(32)
    m = "hey"
    enc = encrypt_message(aes_key, iv, m)
    public_key, private_key = generate_rsa_keypair()
    enc_rsa_key = rsa_encrypt(aes_key, public_key)
    dc = decrypt_message(aes_key, iv, enc)
    print(m)
    print(enc)
    print(enc_rsa_key)
    print(dc)
