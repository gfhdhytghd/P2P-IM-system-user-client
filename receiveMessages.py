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
import os

from rsa import DecryptionError


stopBackgroundThreads = False
screen = ""
prompt = ""
msgToSend = ""
contactOnline = False

"""
Description: Clears the screen in the terminal
Parameters: None
Returns: None
"""
def clear(): os.system('cls' if os.name == 'nt' else 'clear')

"""
Description: Prints a string to the screen and adds it to the screen variable to be printed to the screen later
Parameters: s - The string to print to the screen
Returns: None
"""
def printToScreen(s):
    global screen, prompt
    clear()
    if(s != ''):
        screen += (s + '\n')
    print(screen)
    print(prompt)

"""
Description: Asks the user for input and adds it to the prompt variable to be printed to the screen later
Parameters: p - The prompt to display to the user
Returns: The user's input
"""
def promptToScreen(p):
    global screen, prompt
    clear()
    print(screen)
    s = input(p)
    prompt = p + s
    return s

"""
Description: Check if the provided string is a valid IP address
Parameters: ip - The string to check
Returns: True if the string is a valid IP address, False otherwise
"""
def validateIP(ip):
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

sport = 50003
dport = 50004



latestMessages = []

"""
Description: Decrypts and cleans up the message payload
Parameters: payload - The payload of the message
Returns: The decrypted and cleaned up message
"""
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

"""
Description: Handles any incoming packets and proccesses them accordingly (Called by packet sniffer)
Parameters: pkt - The packet to handle
Returns: None
"""
def packetHandler(pkt):
    global msgToSend

    try:
        sourceIP = pkt[IP].src
        destionationIP = pkt[IP].dst
        destionationPort = pkt[UDP].dport
        sourcePort = pkt[UDP].sport
        
        payload = pkt[UDP].payload
    except Exception as e:
        return
    
    try:
        # Check if the destination IP is in the contact list
        if not contacts.getContactIP(sourceIP) == 'Unknown':
            # Ignore Packets where the destination IP is in the contact list since those are packets sent by this user and not received by this user
            return

        if (destionationPort == 50001 and sourcePort == 50002) or (destionationPort == sport and sourcePort == dport):
            msg = getMessage(payload)
            
            # Ignore keep-alive messages
            if msg == '--KEEP-ALIVE--':
                return
            
            # Check if the message is a request for a public key
            if msg == '--REQUIRE-PUBLIC-KEY--':
                # Check if the public key was already generated
                if not crypto.get_public_key() == None:
                    # Send the public key to the contact
                    print('Sending public key...')

                    sock1 = getSocket(sourceIP)
                    
                    sendPublicKey(sourceIP, sock1)

                    sock1.close()

                return

            # Check if the message is a public key
            if msg.startswith('-----BEGIN RSA PUBLIC KEY-----'):
                # Check if the public key was already saved for this ip
                if contacts.getPublicKey(sourceIP) == 'Unknown':
                    # Save the public key to the contact's file
                    
                    print('Saving public key of Partner...')
                    
                    contacts.savePublicKey(sourceIP, msg)

                return

            # Check if the message is a ping
            if msg == '--PING--':
                # Send a pong response
                sock2 = getSocket(sourceIP)

                # Set the contact's online status to online
                contacts.setOnlineStatus(sourceIP, "Online")

                pong(sourceIP, sock2)

                sock2.close()
                return

            # Check if the message is a pong
            if msg == '--PONG--':
                contacts.setOnlineStatus(sourceIP, "Online")
                return
            
            contactName = contacts.getContactName(sourceIP)

            # Get the timestamp from the message
            timestamp = msg.split('---TIMESTAMP-BEGIN--')[1].split('---TIMESTAMP-END--')[0]

            # Check if the timestamp is older then 2 minutes
            if int(timestamp) < int(time.time()) - 120:
                print('Message from ' + contactName + ' is too old. Ignoring...')
                return

            # Get the message from the message
            msg = msg.split('---TIMESTAMP-END--')[1]

            # Check if the message is a duplicate
            for message in latestMessages:
                if message[0] == sourceIP and message[1] == msg and message[2] == timestamp:
                    return

            # Save the message to the contact's file
            contacts.saveMessage(msg, sourceIP)
            latestMessages.append((sourceIP, msg, timestamp))

            printToScreen(contactName + ": " + msg)

            # Only save the last 20 messages
            if len(latestMessages) > 20:
                latestMessages.pop(0)

    except DecryptionError:
        pass
    except Exception as e:
        print(e)






"""
Description: Sends a message to the specified IP address every 5 seconds to keep the connection alive
Parameters: ip - The IP address to send the message to
            sock - The socket to send the message on
Returns: None
"""
def keepAlive(ip, sock):
    global stopBackgroundThreads

    # Send a message every 5 seconds to keep the connection alive
    while True:
        if stopBackgroundThreads:
            break

        try:
            sock.sendto('--KEEP-ALIVE--'.encode(), (ip, sport))
        except:
            pass

        time.sleep(5)

def pong(ip, sock):
    try:
        sock.sendto('--PONG--'.encode(), (ip, sport))
    except:
        pass

def ping(ip, sock):
    global contactOnline

    contactOnline = False

    sock.sendto('--PING--'.encode(), (ip, sport))

"""
Description: Sends own public key to a IP so they can encrypt messages to you
Parameters: ip - The IP address to send the public key to
            sock - The socket to send the public key on
Returns: None
"""
def sendPublicKey(ip, sock):
    print("Sending public key...")
    publicKey = crypto.get_public_key()
    sock.sendto(publicKey.encode(), (ip, sport))

"""
Description: Asks a contact for their public key so you can encrypt messages to them
Parameters: ip - The IP address to ask the public key from
            sock - The socket to send the request on
Returns: None
"""
def askForPublicKey(ip, sock):
    sock.sendto('--REQUIRE-PUBLIC-KEY--'.encode(), (ip, sport))


"""
Description: Gets a new socket to use for communication
Parameters: targetIP - The IP address to which the socket should be bound
Returns: A socket to use for communication
"""
def getSocket(targetIP):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', sport))
    sock.sendto(b'0', (targetIP, dport))

    sock.close()
    time.sleep(1)


    # send messages
    # equiv: echo 'xxx' | nc -u -p 50002 x.x.x.x 50001
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', dport))

    return sock

try:
    print("Starting packet sniffer...")
    sniff(prn=packetHandler)
except Exception as e:
    # Check if the error is because winpcap is not installed
    print(e)
    if 'winpcap is not installed' in str(e).lower() or 'npcap' in str(e).lower():
        print('Error: WinPcap or Npcap is not installed. Please install WinPcap or Npcap and try again.')

        # Kill the whole program and not just the thread
        os._exit(1)