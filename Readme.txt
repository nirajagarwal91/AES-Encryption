Language Used: Java 
Version: java version "1.8.0_161"
IDE compiled: Eclipse Oxygen Release (4.7.0)

STEPS TO CHECK THE CORRECTNESS OF THE PROGRAM

1. Setup the file path before executing. Program would not run correctly if all the file paths are not set up.
	For Simplicity filepath needs to be set up in only one function getFileData.  
	In my case the file path is 'C:\\Users\\Niraj\\eclipse-workspace\\aes_m12511318\\data\\'. Replace this with the desired location on 
	your computing system.
2. Once the file locations have been set-up. You are ready to run your program. 
3. Before executing if there are any data changes that are required to made to the above file please do it. Names of the files and functions are mentioned below.


NOTE: The Encryption and Decryption Function are self contained. No additional inputs needs to be inserted expect the data in the plaintext.txt file. 

=========================== FILE DESCRIPTION ========================================================================
key.txt           :- contains 256 bit key that is generated randomly
plaintext         :- contains the message to be encrypted. This needs to be input by the user.
iv.txt            :- contains the IV value in Hexadecimal that is secured randomly and stored in the file.
ciphertextECB.txt :- contains the cipher text after encryption using AES - ECB mode
ciphertextCBC.txt :- contains the cipher text after encryption using AES - CBC mode
resultECB.txt     :- contains the decrypted message using AES - ECB mode
resultCBC.txt     :- contains the decrypted message using AES - CBC mode
======================================================================================================================