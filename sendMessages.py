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

sport = 50001
dport = 50002

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

            if key_size < 1024:
                print('Key size must be greater or equal than 1024. Please try again.')
            elif key_size > 4096:
                print('Key size must be less or equal than 4096. Please try again.')
            else:
                key_size_valid = True
        except:
            print('Key size must be an integer')

    print('Generating key pair. This may take a couple minutes...')
    crypto.create_key_pair(key_size)
publicKey = crypto.get_public_key()


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

"""
Description: Sends a message to the specified IP address to ask them if they are online
Parameters: ip - The IP address to send the message to
            sock - The socket to send the message on
Returns: None
"""
def ping(ip, sock):
    contacts.setOnlineStatus(ip, "Offline")

    sock.sendto('--PING--'.encode(), (ip, sport))

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
        
    sock = getSocket(contactIp)    

    stopBackgroundThreads = False
    keepAliveThread = threading.Thread(target=keepAlive, args=(contactIp, sock, ));
    keepAliveThread.start()
    
    # Ping the contact to see if they are online
    ping(contactIp, sock)
    print('Checking if contact is online...')

    # Wait for the contact to respond to the ping
    for x in range(0, 6):
        if contacts.getContactOnlineStatus(contactIp) == "Online":
            break
        time.sleep(1)

    # Check if the contact is online
    if contacts.getContactOnlineStatus(contactIp) == "Online":
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