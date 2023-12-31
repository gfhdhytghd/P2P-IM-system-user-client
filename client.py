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

sock = None

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

sport = 50001
dport = 50002


"""
Description: Background thread that listens for incoming messages
Parameters: listenToIP - The IP address to listen for messages from
            sock - The socket to listen on
Returns: None
"""
def listen(listenToIP, sock):
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

            if destionationPort == 50001 and sourcePort == 50002:
                msg = getMessage(payload)

                # Ignore keep-alive messages
                if msg == '--KEEP-ALIVE--':
                    return
                
                # Check if the message is a request for a public key
                if msg == '--REQUIRE-PUBLIC-KEY--':
                    # Check if the public key was already generated
                    if not crypto.get_public_key() == None:
                        # Send the public key to the contact
                        # Only print the info if the chat with the contact is open
                        if sourceIP == listenToIP:
                            print('Sending public key...')
                        
                        sendPublicKey(sourceIP, sock)

                    return

                # Check if the message is a public key
                if msg.startswith('-----BEGIN RSA PUBLIC KEY-----'):
                    # Check if the public key was already saved for this ip
                    if contacts.getPublicKey(sourceIP) == 'Unknown':
                        # Save the public key to the contact's file
                        # Only print the info if the chat with the contact is open
                        if sourceIP == listenToIP:
                            print('Saving public key of Partner...')
                        
                        contacts.savePublicKey(sourceIP, msg)

                    return

                # Check if the message is a ping
                if msg == '--PING--':
                    # Send a pong response
                    pong(sourceIP, sock)
                    return

                # Check if the message is a pong
                if msg == '--PONG--':
                    if sourceIP == listenToIP:
                        global contactOnline
                        
                        contactOnline = True
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

                # Only save the last 20 messages
                if len(latestMessages) > 20:
                    latestMessages.pop(0)


                """if sourceIP == ip:
                    printToScreen(contactName + ': ' + msg)
                    printToScreen('> ')"""

        except DecryptionError:
            pass
        except Exception as e:
            print(e)

    try:
        sniff(prn=packetHandler)
    except Exception as e:
        # Check if the error is because winpcap is not installed
        print(e)
        if 'winpcap is not installed' in str(e).lower() or 'npcap' in str(e).lower():
            print('Error: WinPcap or Npcap is not installed. Please install WinPcap or Npcap and try again.')

            # Kill the whole program and not just the thread
            os._exit(1)

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

"""
Description: Sends own public key to a IP so they can encrypt messages to you
Parameters: ip - The IP address to send the public key to
            sock - The socket to send the public key on
Returns: None
"""
def sendPublicKey(ip, sock):
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
Description: Prints all the messages from a contact to the screen
Parameters: ip - The IP address of the contact
Returns: None
"""
def printMessages(ip):
    # Load the messages from the contact's file
    messages = contacts.getMessages(ip)

    # Only print the latest 10 messages
    if len(messages) > 10:
        messages = messages[-10:]

    # Print the messages
    for message in messages:
        contactName = contacts.getContactName(message[0])
        printToScreen(contactName + ": " + message[2])

"""
Description: UI Function that Allows the user to send a message to a contact
Parameters: None
Returns: None
"""
def open_conversation():
    global stopBackgroundThreads
    global screen

    screen = ""

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
    
    contacts.setOnlineStatus(contactIp, "Offline")
    
    stopBackgroundThreads = False

    print('\nGot Peer')
    print('  IP:          {}'.format(contactIp))
    print('  Source Port: {}'.format(sport))
    print('  Dest Port:   {}\n'.format(dport))

    # punch hole
    # equiv: echo 'punch hole' | nc -u -p 50001 x.x.x.x 50002
    print('Punching hole...')

    global sock

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

    listener = threading.Thread(target=listen, args=(contactIp, sock,));
    listener.start()

    keepAliveThread = threading.Thread(target=keepAlive, args=(contactIp, sock, ));
    keepAliveThread.start()
    
    # Ping the contact to see if they are online
    ping(contactIp, sock)
    print('Checking if contact is online...')

    # Wait for the contact to respond to the ping
    for x in range(0, 6):
        if contactOnline:
            break
        time.sleep(1)

    # Check if the contact is online
    if contactOnline:
        printToScreen('\n\rContact is online.\n\r')
    else:
        printToScreen('\n\rContact seems to be offline.\n\r')

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

            # Get current timestamp as unix time
            timestamp = int(time.time())

            # Add the timestamp to the message
            msgToSend = '---TIMESTAMP-BEGIN--' + str(timestamp) + '---TIMESTAMP-END--' + msgToSend

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

"""
Description: UI Function that prompts the user to confirm an action
Parameters: prompt - The prompt to display to the user
Returns: True if the user confirms, False if they don't
"""
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

"""
Description: UI Function that closes the program if the user confirms
Parameters: None
Returns: None
"""
def quit():
    if confirm("\nExit? (Y/n) "):
        global sock
        sock.close()
        exit()
    else:
        main_menu()

"""
Description: UI Function that lists all the contacts in the user's contact list
Parameters: None
Returns: None
"""
def list_contacts():
    contactList = contacts.getContactList()

    if len(contactList) == 0:
        print("You have no contacts.")
        return
    
    print("Your contacts:")
    for contact in contactList:
        print(contact[0] + ": " + contact[1])

"""
Description: UI Function that allows the user to delete a contact
Parameters: None
Returns: None
"""
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
    
    try:
        contactName = input("> ")

        # Get the ip of the contact
        contactIP = contacts.getContactIP(contactName)

        # Check if the contact exists
        if contactIP == 'Unknown':
            print("Contact does not exist.")
            return

        # Delete the contact
        contacts.removeContact(contactIP)

        print("Contact deleted.")
    except KeyboardInterrupt:
        main_menu()

"""
Description: UI Function that allows the user to add a new contact
Parameters: None
Returns: None
"""
def new_contact():
    clear()
    print("Enter the Name of the contact you would like to add.")
    try:
        contactName = input("> ")

        # Check if the contact already exists
        if contacts.getContactIP(contactName) != 'Unknown':
            print("Contact already exists.")
            return
        # Check if the contact name is valid
        if contactName == '':
            print("Invalid contact name.")
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
    except KeyboardInterrupt:
        main_menu()

"""
Description: UI Function that shows all the Options for the user to choose from
Parameters: None
Returns: None
"""
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
        print("Your fingerprint is: \n\r" + crypto.get_public_key())
    elif command == "q":
        quit()
    else:
        print("Invalid command. Please try again.")
        main_menu()
    
    try:
        print("\nPress Ctrl+C to return to the main menu.")
        while True:
            pass
    except KeyboardInterrupt:
        main_menu()

main_menu()