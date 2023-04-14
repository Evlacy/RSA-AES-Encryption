import socket
from rsa_python import rsa
import random
import hashlib
import pyAesCrypt
import os
import datetime

class Server:
    def __init__(self, port):
        # get the hostname
        host = socket.gethostname()
        self.server_socket = socket.socket()  # get instance
        # look closely. The bind() function takes tuple as argument
        self.server_socket.bind((host, port))  # bind host address and port together
        self.conn = None

    def waitForConnection(self):
        # configure how many client the server can listen simultaneously
        self.server_socket.listen(2)
        self.conn, address = self.server_socket.accept()  # accept new connection
        print("Connection from: " + str(address))
        return address

    def sendMessage(self, msg: str):
        #print("Sending:", msg)
        self.conn.send(str.encode(msg))

    def receiveMessage(self):
        return self.conn.recv(4096).decode()

    def sendFile(self, filename: str):
        print("Sending:", filename)
        with open(filename, 'rb') as f:
            raw = f.read()
        # Send actual length ahead of data, with fixed byteorder and size
        self.conn.sendall(len(raw).to_bytes(8, 'big'))
        self.conn.send(raw)  # send data to the client

    def close(self):
        if not self.conn == None:
            self.conn.close()  # close the connection
        else:
            raise Exception("Erreur: la connection a été fermée avant d'être instanciée.")
        
    def generateServerKeys(self):
        self.pubkeys = rsa.generate_key_pair(512)

def hash(filePath):
    fileObj = open(filePath, 'rb')
    m = hashlib.md5()
    while True:
        d = fileObj.read(8096)
        if not d:
            break
        m.update(d)
    return m.hexdigest()

if __name__ == '__main__':
    # init server 
    server = Server(5000)
    ip = server.waitForConnection()

    # receive hostname 
    hostname = server.receiveMessage()

    # generate keys
    server.generateServerKeys()

    # sending the files list
    directory = "input/files"
    str_of_files = ""
    for fichier in os.listdir(directory):
        str_of_files += fichier + "\n"

    server.sendMessage(str_of_files)

    # receive asked file
    asked_file = server.receiveMessage()

    # receive rsa keys
    e = int(server.receiveMessage())
    n = int(server.receiveMessage())

    # sending public and modulus part of the server keys
    server.sendMessage(str(server.pubkeys["public"]))
    server.sendMessage(str(server.pubkeys["modulus"]))

    # generate a random number for encryption
    aes_key = str(random.randint(1, 1000000000000))

    # encrypting the key with rsa and sending it
    encrypt_key = rsa.encrypt(aes_key, int(e), int(n))
    server.sendMessage(str(encrypt_key))

    # encrypting the file with aes and sending it
    decrypted_file = "input/files/" + asked_file
    encrypted_file = "input/encrypted_files/" + asked_file + ".aes"
    pyAesCrypt.encryptFile(decrypted_file, encrypted_file, aes_key)
    server.sendFile(filename=encrypted_file)
    
    # calculate the hash of the file
    hash_of_the_server = hash(encrypted_file)
    server.sendMessage(hash_of_the_server)

    log_sys = open('log/logs.txt', 'r')
    contenu = log_sys.read()
    log_sys.close 

    log_sys = open('log/logs.txt', 'w')
    log_sys.write(contenu + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + 
                  "\nIP : " + str(ip[0]) + " / Port : " + str(ip[1]) + 
                  "\nHostname : " + hostname + 
                  "\nFile : " + asked_file + "\n\n")
    log_sys.close
    
    os.remove(encrypted_file)    
    server.close()