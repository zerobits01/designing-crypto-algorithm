#ifndef RC4_h
#define RC4_h
#include <stdio.h>

void RC4(unsigned char*,long , unsigned char* , long ,unsigned char* );
/* Function to encrypt data represented in array of char "data" with length represented in dataLen using key which is represented in "Key" with length represented in keyLen, and result will be stored in result */

void RC4_KSG(long , unsigned char* , long ,unsigned char* );
#endif /* RC4_h */
