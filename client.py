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

def clear(): os.system('cls' if os.name == 'nt' else 'clear')

stopBackgroundThreads = False
screen = ""
prompt = ""
msgToSend = ""

def printToScreen(s):
    global screen, prompt
    clear()
    if(s != ''):
        screen += (s + '\n')
    print(screen)
    print(prompt)

def promptToScreen(p):
    global screen, prompt
    clear()
    print(screen)
    s = input(p)
    prompt = p + s
    return s

def validateIP(ip):
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

sport = 50001
dport = 50002



def listen(listenToIP, sock):

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

            if destionationPort == 50001 and sourcePort == 50002 and sourceIP == listenToIP:
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
                        sendPublicKey(sourceIP, sock)

                    return

                # Check if the message is a public key
                if msg.startswith('-----BEGIN RSA PUBLIC KEY-----'):
                    # Check if the public key was already saved for this ip
                    if contacts.getPublicKey(sourceIP) == 'Unknown':
                        # Save the public key to the contact's file
                        print('Saving public key of Partner...')
                        contacts.savePublicKey(sourceIP, msg)

                    return
                
                contactName = contacts.getContactName(sourceIP)

                # Save the message to the contact's file
                contacts.saveMessage(msg, sourceIP)
                
                """if sourceIP == ip:
                    printToScreen(contactName + ': ' + msg)
                    printToScreen('> ')"""

        except Exception as e:
            print(e)

    try:    
        sniff(prn=packetHandler)
    except Exception as e:
        # Check if the error is because winpcap is not installed
        print(e)
        if 'winpcap is not installed' in str(e).lower():
            print('Error: WinPcap or Npcap is not installed. Please install WinPcap or Npcap and try again.')

            # Kill the whole program and not just the thread
            os._exit(1)


def keepAlive(ip, sock):
    # Send a message every 5 seconds to keep the connection alive
    while True:
        if stopBackgroundThreads:
            break

        try:
            sock.sendto('--KEEP-ALIVE--'.encode(), (ip, sport))
        except:
            pass

        time.sleep(5)

# Generate a key pair if one doesn't exist
if crypto.get_public_key() == None:
    print('You do not have a key pair yet. You will need to generate one now.')
    print('Enter the size of the key you would like to generate.')
    print('Recommended Options (The higher the number the more Secure, but the longer it takes to generate): [1024, 2048, 4096]')
    key_size_valid = False
    while key_size_valid == False:
        key_size = input('> ')

        # Check if the key size is valid
        try:
            key_size = int(key_size)

            if key_size <= 1024:
                print('Key size must be greater or equal than 1024. Please try again.')
            elif key_size >= 4096:
                print('Key size must be less or equal than 4096. Please try again.')
            else:
                key_size_valid = True
        except:
            print('Key size must be an integer')

    print('Generating key pair. This may take a couple minutes...')
    crypto.create_key_pair(key_size)
publicKey = crypto.get_public_key()

def sendPublicKey(ip, sock):
    sock.sendto(publicKey.encode(), (ip, sport))

def askForPublicKey(ip, sock):
    sock.sendto('--REQUIRE-PUBLIC-KEY--'.encode(), (ip, sport))

def printMessages(ip):
    # Load the messages from the contact's file
    messages = contacts.getMessages(ip)

    # Print the messages
    for message in messages:
        contactName = contacts.getContactName(message[0])
        printToScreen(contactName + ": " + message[2])

def open_conversation():

    # Ask which contact to open
    print('Which contact would you like to open?\n')
    list_contacts()

    try:
        # Get the contact's name
        contactName = input('> ')
    except KeyboardInterrupt:
        main_menu()

    contactIp = contacts.getContactIP(contactName)

    # Check if the contact exists
    if contactIp == 'Unknown':
        print('Contact does not exist. Please try again.')
        return
    
    stopBackgroundThreads = False

    print('\nGot Peer')
    print('  IP:          {}'.format(contactIp))
    print('  Source Port: {}'.format(sport))
    print('  Dest Port:   {}\n'.format(dport))

    # punch hole
    # equiv: echo 'punch hole' | nc -u -p 50001 x.x.x.x 50002
    print('Punching hole...')

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', sport))
    sock.sendto(b'0', (contactIp, dport))

    print('Success! Ready to exchange keys\n')
    sock.close()
    time.sleep(1)


    # send messages
    # equiv: echo 'xxx' | nc -u -p 50002 x.x.x.x 50001
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', dport))

    listener = threading.Thread(target=listen, args=(contactIp, sock,), daemon=True);
    listener.start()

    keepAliveThread = threading.Thread(target=keepAlive, args=(contactIp, sock, ), daemon=True);
    keepAliveThread.start()
    
    printMessages(contactIp)
    try:
        print("\nPress Ctrl+C to return to the main menu.")
        while(True):
            # Ask the partner to send their public key if we don't have it
            if contacts.getPublicKey(contactIp) == 'Unknown':
                print('Asking for public key...')
                askForPublicKey(contactIp, sock)
                time.sleep(5)
                continue

            msgToSend = promptToScreen('> ')
            printToScreen('You: ' + msgToSend)
            contacts.saveOutgoingMessage(msgToSend, contactIp)

            # Encrypt the message
            partnerPublicKey = contacts.getPublicKey(contactIp)
            msgToSend = crypto.encrypt_message(msgToSend, rsa.PublicKey.load_pkcs1(partnerPublicKey))

            sock.sendto(msgToSend, (contactIp, sport))
    except KeyboardInterrupt:
        # Close the socket
        sock.close()

        # Stop the background threads
        stopBackgroundThreads = True

        main_menu()

def confirm(prompt):
    """Prompts the user for a yes/no response."""
    while True:
        response = input(prompt).lower()
        if response in ['y', 'yes']:
            return True
        elif response in ['n', 'no']:
            return False
        else:
            print("Please enter 'y' or 'n'.")

def quit():
    if confirm("\nExit? (Y/n) "):
        exit()
    else:
        main_menu()

def list_contacts():
    contactList = contacts.getContactList()

    if len(contactList) == 0:
        print("You have no contacts.")
        return
    
    print("Your contacts:")
    for contact in contactList:
        print(contact[0] + ": " + contact[1])


def delete_contact():
    contactList = contacts.getContactList()
    clear()

    if len(contactList) == 0:
        print("You have no contacts.")
        return

    print("Your contacts:")
    for contact in contactList:
        print(contact[0] + ": " + contact[1])

    print("\nEnter the Name of the contact you would like to delete.")
    contactName = input("> ")

    # Get the ip of the contact
    contactIP = contacts.getContactIP(contactName)

    # Check if the contact exists
    if contactIP == 'Unknown':
        print("Contact does not exist.")
        return

    # Delete the contact
    contacts.deleteContact(contactIP)

    print("Contact deleted.")

def new_contact():
    clear()
    print("Enter the Name of the contact you would like to add.")
    contactName = input("> ")

    # Check if the contact already exists
    if contacts.getContactIP(contactName) != 'Unknown':
        print("Contact already exists.")
        return

    print("Enter the IP of the contact you would like to add.")

    # Check if the ip is valid
    ipAddressValid = False
    while ipAddressValid == False:
        contactIP = input("> ")

        # Check if the IP address format is valid
        if validateIP(contactIP):
            ipAddressValid = True
        else:
            print("Invalid IP address")
    
    # Add the contact
    contacts.addContact(contactIP, contactName)

    print("Contact added.")


def main_menu():
    clear()

    print("Enter a command...")
    print("oc   -> Open Conversation")
    print("nc   -> New Contact")
    print("lc   -> List Contacts")
    print("dc   -> Delete Contact")
    print("fp   -> Display Fingerprint")
    print("q    -> Quit\n")

    command = input("> ").lower()

    if command == "oc":
        open_conversation()
    elif command == "nc":
        new_contact()
    elif command == "lc":
        clear()
        list_contacts()
    elif command == "dc":
        delete_contact()
    elif command == "fp":
        print("Your fingerprint is: " + crypto.get_fingerprint())
    elif command == "q":
        quit()
    else:
        print("Invalid command. Please try again.")
        main_menu()
    
    try:
        print("\nPress Ctrl+C to return to the main menu.")
        while True: ### YOUR CODDE
            pass    ### 
    except KeyboardInterrupt:
        main_menu()

main_menu()