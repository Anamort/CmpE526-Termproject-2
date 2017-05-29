# CmpE526-Termproject-2



## Objective and Abstract of the Project
The goal of this project is to implement an encryption/decryption program by using one of the symmetric key algorithms such as AES and DES, and to authenticate user of the program utilizing public key cryptography. Moreover, the program must work recursively in a directory selected by authenticated user. In this study, AES algorithm is used as symmetric encryption/decryption algorithm while RSA is used for public-key cryptography. The user can create several public-private key pair indicating the id number and its password, and store the private key which is encrypted by the program in an external device for the security. The program is implemented by using the C programming language.

## Design of the Program
The program consists of four general modules:
• AES algorithm [1] for symmetric encryption/decryption
• RSA algorithm [2] for public key encryption/decryption
• SHA1 algorithm [3] used to hash the password of the user
• The Main module to manage the program

## Main Module

This module is the brain of the project. It manages other three modules considering the requirements of the project. First, the user is asked about his/her password. If it is the first time that the user use the program, then he/she is able to type new password. Afterwards, user’s encrypted private key is read from a directory indicated by user. If this second authentication process is successful, user can use the main program capabilities including encryption, decryption, changing password, and creating new private-public key pair.
Encryption and decryption processes is based on the AES algorithm. In this module, when reading the encrypting file, blocks of 16-bytes are used. For each iteration, a block is read from file, encrypted, and written into the same file. Same process is applied for the decryption in reverse manner. By using the same file for both encryption and decryption, memory efficiency is provided.


## References

[1]https://github.com/dhuertas/AES 
[2] https://github.com/pantaloons/RSA 
[3] https://github.com/clibs/sha1
