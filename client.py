import socket
import sys
import threading
from scapy.all import *
import binascii
import ast
import time

import contacts
import crypto

import rsa

"""
rendezvous = ('147.182.184.215', 55555)

# connect to rendezvous
print('connecting to rendezvous server')

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('0.0.0.0', 50001))
sock.sendto(b'0', rendezvous)

while True:
    data = sock.recv(1024).decode()

    if data.strip() == 'ready':
        print('checked in with server, waiting')
        break


data = sock.recv(1024).decode()
ip, sport, dport = data.split(' ')
sport = int(sport)
dport = int(dport)
"""


print("Enter the IP Address for your new contact...")
ipAddressValid = False
while ipAddressValid == False:
    ip = input('> ')

    # Check if the IP address format is valid
    try:
        socket.inet_aton(ip)
        ipAddressValid = True
    except socket.error:
        print("Invalid IP address")

sport = 50001
dport = 50002

print('\nGot Peer')
print('  IP:          {}'.format(ip))
print('  Source Port: {}'.format(sport))
print('  Dest Port:   {}\n'.format(dport))

# punch hole
# equiv: echo 'punch hole' | nc -u -p 50001 x.x.x.x 50002
print('Punching hole...')

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('0.0.0.0', sport))
sock.sendto(b'0', (ip, dport))

print('Success! Ready to exchange keys\n')
sock.close()

# listen for
# equiv: nc -u -l 50001
"""def listen():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    sock.bind(('0.0.0.0', sport))
    
    while True:
        data = sock.recv(1024)
        print('\rpeer: {}\n> '.format(data.decode()), end='')

listener = threading.Thread(target=listen, daemon=True);
listener.start()
"""

def listen():

    def getMessage(payload):
        try:
            msg = bytes(payload).decode('utf8')

            # Clean up the message to remove null bytes
            msgRaw = [ord(c) for c in msg.strip()]
            msgRaw = [x for x in msgRaw if x != 0]

            cleanedMsg = ''
            for char in msgRaw:
                cleanedMsg += chr(char)
        except:
            cleanedMsg = crypto.decrypt_message(bytes(payload), crypto.get_private_key()).encode()

            # Convert the message to a string
            cleanedMsg = cleanedMsg.decode('utf8')

        return cleanedMsg

    def packetHandler(pkt):
        try:
            sourceIP = pkt[IP].src
            destionationIP = pkt[IP].dst
            destionationPort = pkt[UDP].dport
            sourcePort = pkt[UDP].sport
            
            payload = pkt[UDP].payload
        except Exception as e:
            return
        
        try:

            if sourceIP == ip and destionationPort == 50001 and sourcePort == 50002:
                msg = getMessage(payload)

                # Ignore keep-alive messages
                if msg == '--KEEP-ALIVE--':
                    return
                
                # Check if the message is a request for a public key
                if msg == '--REQUIRE-PUBLIC-KEY--':
                    # Send the public key to the contact
                    print('Sending public key...')
                    sendPublicKey()

                    return

                # Check if the message is a public key
                if msg.startswith('-----BEGIN RSA PUBLIC KEY-----'):
                    # Save the public key to the contact's file
                    print('Saving public key of Partner...')
                    contacts.savePublicKey(sourceIP, msg)

                    return
                
                contactName = contacts.getContactName(sourceIP)

                # Check if contact already exists
                if not contactName == 'Unknown':
                    # Save the message to the contact's file
                    contacts.saveMessage(sourceIP, msg)
                
                print(contactName + ': ' + msg)
                print('> ')
        except Exception as e:
            print(e)
        
    sniff(prn=packetHandler)

listener = threading.Thread(target=listen, daemon=True);
listener.start()


# send messages
# equiv: echo 'xxx' | nc -u -p 50002 x.x.x.x 50001
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('0.0.0.0', dport))

def keepAlive():
    # Send a message every 5 seconds to keep the connection alive
    while True:
        sock.sendto('--KEEP-ALIVE--'.encode(), (ip, sport))

        time.sleep(5)

keepAlive = threading.Thread(target=keepAlive, daemon=True);
keepAlive.start()

# Generate a key pair if one doesn't exist
crypto.create_key_pair()
publicKey = crypto.get_public_key()

def sendPublicKey():
    sock.sendto(publicKey.encode(), (ip, sport))

def askForPublicKey():
    sock.sendto('--REQUIRE-PUBLIC-KEY--'.encode(), (ip, sport))
    

while True:
    # Ask the partner to send their public key if we don't have it
    if contacts.getPublicKey(ip) == 'Unknown':
        askForPublicKey()
        time.sleep(5)
        continue

    msg = input('> ')

    # Encrypt the message
    partnerPublicKey = contacts.getPublicKey(ip)
    msg = crypto.encrypt_message(msg, rsa.PublicKey.load_pkcs1(partnerPublicKey))

    sock.sendto(msg, (ip, sport))


