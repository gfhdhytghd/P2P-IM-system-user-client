import socket
import sys
import threading
from scapy.all import *
import binascii
import ast
import time
import contacts

def addContact(ip, name):
    # Save the new contact to the contacts file
    with open('contacts.txt', 'a') as contactsFile:
        contactsFile.write(name + ' | ' + ip + '\n')

def removeContact(ip):
    # Remove the contact from the contacts file
    with open('contacts.txt', 'r') as contactsFile:
        lines = contactsFile.readlines()

    with open('contacts.txt', 'w') as contactsFile:
        for line in lines:
            if line.split(' | ')[1] != ip:
                contactsFile.write(line)

def savePublicKey(ip, public_key):
    # Save the public key to the public_keys file
    # Remove all newlines from the public key
    public_key = public_key.replace('\n', 'NEWLINE')

    with open('public_keys.txt', 'a') as publicKeysFile:
        publicKeysFile.write(ip + ' | ' + public_key + '\n')

def getPublicKey(ip):
    try:
        # Get the public key from the public_keys file
        with open('public_keys.txt', 'r') as publicKeysFile:
            for line in publicKeysFile:
                line = line.strip()
                if line.split(' | ')[0] == ip:
                    return line.split(' | ')[1].replace('NEWLINE', '\n')
    except:
        pass

    # If the public key is not in the public_keys file, return 'Unknown'
    return 'Unknown'

def getContactName(ip):

    if ip == 'You':
        return 'You'

    try:
        # Get the name of the contact from the contacts file
        with open('contacts.txt', 'r') as contactsFile:
            for line in contactsFile:
                line = line.strip()
                if line.split(' | ')[1] == ip:
                    return line.split(' | ')[0]
    except:
        pass

    # If the contact is not in the contacts file, return 'Unknown'
    return 'Unknown'

def getContactIP(name):
    try:
        # Get the IP address of the contact from the contacts file
        with open('contacts.txt', 'r') as contactsFile:
            for line in contactsFile:
                line = line.strip()
                if line.split(' | ')[0] == name:
                    return line.split(' | ')[1]
    except:
        pass

    # If the contact is not in the contacts file, return 'Unknown'
    return 'Unknown'

def getContactList():
    try:
        # Get the list of contacts from the contacts file
        contactList = []
        with open('contacts.txt', 'r') as contactsFile:
            for line in contactsFile:
                line = line.strip()
                contactList.append(line.split(' | '))
    except:
        pass

    return contactList

def getContactListIP():
    try:
        # Get the list of contacts from the contacts file
        contactList = []
        with open('contacts.txt', 'r') as contactsFile:
            for line in contactsFile:
                line = line.strip()
                contactList.append(line.split(' | ')[1])
    except:
        pass

    return contactList

def saveMessage(message, ip):
    # Save the message to a messages file for the ip
    currentDatetime = time.strftime('%Y-%m-%d %H:%M:%S')
    with open(str(ip)+'_messages.txt', 'a') as messagesFile:
        messagesFile.write(ip + " | " + currentDatetime + ' | ' + message + '\n')
        

def saveOutgoingMessage(message, ip):
    # Save the message to the messages file
    currentDatetime = time.strftime('%Y-%m-%d %H:%M:%S')
    with open(str(ip)+'_messages.txt', 'a') as messagesFile:
        messagesFile.write("You | " + currentDatetime + ' | ' + message + '\n')

def getMessages(ip):
    # Get the messages from the messages file
    messages = []
    try:
        with open(str(ip)+'_messages.txt', 'r') as messagesFile:
            for line in messagesFile:
                line = line.strip().split(' | ')
                messages.append([line[0], line[1], line[2]])
    except:
        pass

    return messages