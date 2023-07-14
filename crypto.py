import time
import os
import rsa

def create_key_pair(key_size=2048):

    # Check if the key pair already exists
    if os.path.isfile('public_key.pem') and os.path.isfile('private_key.pem'):
        return

    # Generate a key pair
    (public_key, private_key) = rsa.newkeys(key_size)

    # Save the public key to a file
    with open('public_key.pem', 'w+') as public_key_file:
        public_key_file.write(public_key.save_pkcs1().decode())
    
    # Save the private key to a file
    with open('private_key.pem', 'w+') as private_key_file:
        private_key_file.write(private_key.save_pkcs1().decode())

def get_public_key():
    try:
        # Get the public key from the public_key.pem file
        with open('public_key.pem', 'r') as public_key_file:
            return public_key_file.read()
    except:
        return None
    
def get_private_key():
    # Get the private key from the private_key.pem file
    with open('private_key.pem', 'r') as private_key_file:
        return rsa.PrivateKey.load_pkcs1(private_key_file.read())
    
def encrypt_message(message, public_key):
    # Encrypt the message with the public key
    return rsa.encrypt(message.encode(), public_key)

def decrypt_message(message, private_key):
    # Decrypt the message with the private key
    return rsa.decrypt(message, private_key).decode()