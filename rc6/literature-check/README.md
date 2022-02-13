This project is based on the paper The RC6 Block Cipher
Link of the paper:  https://people.csail.mit.edu/rivest/pubs/RRSY98.pdf



Variant key size is used here: from 24 to 256 more than that will be ignored and lower than that will be filled with 0;

here we checked only one block of 96bits, and this is for passing the course test.

eg.

Encryption
plaintext: 00 00 00 00 00 00 00 00 00 00 00 00 
userkey: 00 00 00 00 00 00 00 00 00 00 00 00

Decryption
ciphertext: 8f c3 a5 36 56 b1 f7 78 c1 29 df 4e 
userkey: 00 00 00 00 00 00 00 00 00 00 00 00 