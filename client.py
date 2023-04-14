import socket
from rsa_python import rsa
import hashlib
import pyAesCrypt
import os

class Client:
    def __init__(self, port):
        self.host = socket.gethostname()  # as both code is running on same pc
        self.port = port
        self.client_socket = socket.socket()  # instantiate
        self.bfile = None

    def connect(self):
        self.client_socket.connect((self.host, self.port))  # connect to the server

    def receiveFile(self):
        # receive the size of the file
        expected_size = b""
        while len(expected_size) < 8:
            more_size = self.client_socket.recv(8 - len(expected_size))
            if not more_size:
                raise Exception("Short file length received")
            expected_size += more_size

        # Convert to int, the expected file length
        expected_size = int.from_bytes(expected_size, 'big')

        # Until we've received the expected amount of data, keep receiving
        self.bfile = b""  # Use bytes, not str, to accumulate
        while len(self.bfile) < expected_size:
            buffer = self.client_socket.recv(expected_size - len(self.bfile))
            if not buffer:
                raise Exception("Incomplete file received")
            self.bfile += buffer
        return self.bfile

    def receiveMessage(self):
        return self.client_socket.recv(8192).decode()

    def sendMessage(self, msg: str):
        #print("Sending:", msg)
        self.client_socket.send(str.encode(msg))

    def saveFile(self, bytes: b"", filename: str):
        with open(filename, 'wb') as f:
            f.write(self.bfile)

    def close(self):
        if not self.client_socket == None:
            self.client_socket.close()  # close the connection
        else:
            raise Exception("Erreur: la connection a été fermée avant d'être instanciée.")
        
    def generateClientKeys(self):
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
    # init client
    client = Client(5000)
    client.connect()

    # send hostname
    client.sendMessage(client.host)

    # generate keys
    client.generateClientKeys()

    # receive all files and choose one
    files = client.receiveMessage()
    asked_file = input("Which file do you want ? (ex: testing.txt) \n"+ files)

    # sending the asked file
    client.sendMessage(asked_file)

    # sending public and modulus part of the client keys
    client.sendMessage(str(client.pubkeys["public"]))
    client.sendMessage(str(client.pubkeys["modulus"]))

    # receive rsa keys
    e = int(client.receiveMessage())
    n = int(client.receiveMessage())

    # receive encrypted key  
    encrypted_key = client.receiveMessage()
    
    # decrypt the key
    decrypted_key = rsa.decrypt(str(encrypted_key), client.pubkeys["private"], client.pubkeys["modulus"])

    # receive the file
    bfile = client.receiveFile()

    # path of the files
    encrypted_file = "output/"+ asked_file +".aes"
    decrypted_file = "output/"+ asked_file

    # save the file
    client.saveFile(bytes=bfile, filename=encrypted_file)

    # calculate the hash and receive the hash calculate by the server
    hash_of_the_client = hash(encrypted_file)
    hash_of_the_server = client.receiveMessage()

    print("Hash of the client : " + str(hash_of_the_client))
    print("Hash of the server : " + str(hash_of_the_server))

    # testing the hash
    if str(hash_of_the_client) == str(hash_of_the_server) :
        pyAesCrypt.decryptFile(encrypted_file, decrypted_file, decrypted_key)
        # remove the encrypted file
        os.remove(encrypted_file)
        print("The file has been decrypted.")
    else :
        print("Error : the hash of the file is not the same as the hash of the server.")
        
    client.close()


