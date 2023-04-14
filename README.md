# R4.C.08 (Cryptography) - Overview

The goal of this course is to build a secured file transfer application in Python. 
The client-server architecture is already given in this repository, all you have to do is to add your code to encrypt and decrypt messages and files, and to compute files' hashes.

# Goal

The server will wait the client connection. Once it is connected, the server will securely send a binary file to the client which will save it to its own disk.

# What to do

Here a step-by-step todo list to build the required application:

-------- Secure the key transfer with RSA ----------

1. generate RSA public and private keys on both side (client & server)
2. exchange public keys to initiate a secured communication
3. the server must generate a key to encrypt the file (to send) with AES
4. the server's key is crypted with the client's public key and sent to it
5. the client receives the key and decrypt it

-------- Compute the file's hash ----------

6. the server computes the hash of its encrypted file with SHA-3
7. the server encrypts the hash with the client's public key and send it
8. the client received the hash and decrypt it with its private key

-------- Secure the file transfer with AES ----------

9. the server encrypts its file with AES and send it to the client
10. the client receives the file and compute the hash value of this file. It compares the hash to the received one
11. the client decrypts the file with the key received 
12. the client stores the uncrypted file on its disk
