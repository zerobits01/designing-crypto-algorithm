#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <inttypes.h>
#include "RC4.h"

#define true 1
#define false 0
#define BYTE_TO_BINARY_PATTERN "%c%c%c%c%c%c%c%c"
#define BYTE_TO_BINARY(byte)  \
  (byte & 0x80 ? '1' : '0'), \
  (byte & 0x40 ? '1' : '0'), \
  (byte & 0x20 ? '1' : '0'), \
  (byte & 0x10 ? '1' : '0'), \
  (byte & 0x08 ? '1' : '0'), \
  (byte & 0x04 ? '1' : '0'), \
  (byte & 0x02 ? '1' : '0'), \
  (byte & 0x01 ? '1' : '0') 





void bin(unsigned n){
    unsigned i;
    int a[8];
    printf(BYTE_TO_BINARY_PATTERN"\n", BYTE_TO_BINARY(n));
}


//Function to read file by getting pointer to the file name to return the file contents and file size
unsigned char * readFile(FILE *f,long *fsize){
    unsigned char * data;
    fseek (f,0,2);
    long x =ftell(f);
    *fsize = x;
    fseek (f,0,0);
    data = (unsigned char *) calloc(*fsize+10,sizeof(unsigned char));
    memset (data,0,*fsize+10);
    fread(data,1,*fsize,f);
    fclose (f);
    return data;
}


int isPrefix(char* str, int len, int i, int k){
    // k length sub-string cannot start at index i
    if (i + k > len)
        return false;
    for (int j = 0; j < k; j++)
    {

        // Character mismatch between the prefix
        // and the sub-string starting at index i
        if (str[i] != str[j])
            return false;
        i++;
    }
    return true;
}


int isKPeriodic(char* str, int len, int k){
    // Check whether all the sub-strings
    // str[0, k-1], str[k, 2k-1] ... are equal
    // to the k length prefix of the string
    for (int i = k; i < len; i += k)
        if (!isPrefix(str, len, i, k))
            return false;
    return true;
}


void check_autocorr_uni(char* str, int len){
    int start_indx = 1;
    while(start_indx < len){
        // int count = 0;
        int i = 0;
        int j = start_indx;
        int A = 0;
        int D = 0;
        while(j < len)
            if(str[i++] == str[j++]){
                A++;
            }else{
                D++;
            }
        printf("%d shift has autocorr %d/%d!\n", start_indx, (A-D)/len);
        start_indx++;
    }
}


void check_autocorr_cryptool_mode(char* str, int len){
    printf("\n# checking autocorrelation in cryptool format!\n");
    int start_indx = 1;
    while(start_indx < len){
        // int count = 0;
        int i = 0;
        int j = start_indx;
        int A = 0;
        while(j < len)
            if(str[i++] == str[j++]){
                A++;
            }
        printf("%d shift autocor is %d!\n", start_indx, A);
        start_indx++;
    }
}


void do_checks(char *Cypher, int size){

	printf("# %s, size is %d\n", Cypher, size);
    int unperiod_flag = true;

    char new_str[size*8+1];
    for(int i=0; i < size; i++){
        char tmp[8];
        sprintf(
            tmp, BYTE_TO_BINARY_PATTERN, BYTE_TO_BINARY(Cypher[i])
        );
        for(int j=0; j < 8; j++){
            char t = tmp[j]; 
            // if we directly point the new_str items to tmp[] they will be pointers!
            new_str[i*8 + j] = t;
            
            // printf("<%d:%c>", (i*8 + j), new_str[i*8 + j]);
        }
    }
    new_str[size*8] = '\0';
    printf("\n");
    printf("binary stream: %s\n", new_str);

    // char *tmp_per = "01010101";
    // printf("test k-periodic\n");
    // if(isKPeriodic(tmp_per, 8, 1) || isKPeriodic(tmp_per, 8, 2) || isKPeriodic(tmp_per, 8, 3)){
    //     printf("test k-periodic work\n");
    // }

    // fsize can be the string size	
	// TODO: 1. check k-periodic
    for(int i=1; i < size*8; i++){
        if(isKPeriodic(new_str, size*8, i)){
            printf("the string is %d-preiodic\n", i);
            unperiod_flag = false;
            break;
        }
    }

    if(unperiod_flag){
        printf("\nthe stream is not periodic.\n");
    }

	// TODO: 2. check each run count
    int last_indx = 0;
    char run_check = new_str[0];
    int runs_probability[] = {0,0,0,0,0}; // checking only till 4 length / zero is for all count
    int count_0 = 0;
    int count_1 = 0;
    while(1){
        int count = 0;
        while(1){
            count++;
            if((++last_indx) == size*8 || new_str[last_indx] != run_check){
                break;
            }
        }
        printf("run %c bit-count is %d\n", run_check, count);
        if(run_check == '0'){
            count_0+=count;
        }else if(run_check == '1'){
            count_1+=count;
        }
        runs_probability[0] += count; // saving length again
        if(count == 1){
            runs_probability[1] += count;
        }else if(count == 2){
            runs_probability[2] += count;
        }else if(count == 3){
            runs_probability[3] += count;
        }else if(count == 4){
            runs_probability[4] += count;
        }
        run_check = new_str[last_indx];
        if(last_indx == (size*8)){
            break;
        }
    }
    printf("# len string is %d\n\n", runs_probability[0]);

    printf("# len of all 0s is %d\n", count_0);
    printf("# percent of 0s %f\n", (float)count_0/runs_probability[0]);
    printf("# len of all 1s is %d\n", count_1);
    printf("# percent of 1s %f\n\n", (float)count_1/runs_probability[0]);

    printf("# 1-len run percent is %f\n", (float)runs_probability[1]/runs_probability[0]);
    printf("# 2-len run percent is %f\n", (float)runs_probability[2]/runs_probability[0]);
    printf("# 3-len run percent is %f\n", (float)runs_probability[3]/runs_probability[0]);
    printf("# 4-len run percent is %f\n\n", (float)runs_probability[4]/runs_probability[0]);



	// TODO: 3. check autocorrelation
    check_autocorr_cryptool_mode(new_str, size*8+1);

	// TODO: 4. check Linear Complexity 

}


// function to decrypt data in the sourceFile using keyFile then store the Cipher in resultFile
void Encryptor(const char *sourceFile, const char  *keyFile, const char *resultFile, int keylen){
    unsigned char * data;
    unsigned char * Cypher;
    unsigned char * KS;
    long fsize,ksize ;

    FILE * f = fopen (sourceFile,"rb");
    data = readFile(f,&fsize);
    Cypher = (unsigned char *) calloc(fsize+10,sizeof(unsigned char));
    KS = (unsigned char *) calloc(keylen+10,sizeof(unsigned char));
    memset (Cypher,0,fsize+10);
    unsigned char* key;
    f = fopen (keyFile,"rb");
    key = readFile(f,&ksize);
    
    if(ksize > 256) // check length key to keep sure that it's less than or equal 256 byte
    {
        printf("Key length can not be more than 256 byte according to the RC4 algorithm");
        exit(0);
    }
    
    //printing plain text on console
    printf("Plain Text from %s:\n%s\n",sourceFile, data);
    
    //printing Key text on console
    printf("Key from %s:\n%s\n",keyFile, key);
    
    //Calling the RC4 function to do the encryption and return result in Cypher
    RC4(data, fsize-1, key,ksize,Cypher);
    RC4_KSG(keylen, key,ksize,KS);

    
    //printing Cipher result on console to the user in HEX format
    printf("\nCipher written to %s: \n",resultFile);
    for (int i = 0 ; i < fsize-1;i++)
    {
        printf("%02hhX  ",Cypher[i]);
    }
    printf("\n\n");
    
    /* Write Cipher to the resultFile */
    f = fopen(resultFile, "w");
    fwrite(Cypher, 1, fsize, f);
    fclose(f);


	printf("\n\n###### check on key ######\n\n");
    do_checks(KS, keylen);


	// printf("\n\n###### check on cipher ######\n\n");
	// do_checks(Cypher, fsize-1);

	
    //release the pointers in memory
    free (data);
    free (Cypher);
    free (key);
}


void Decryptor(const char *sourceFile, const char  *keyFile, const char *resultFile){
    unsigned char * data;
    unsigned char * Cypher;
    long fsize,ksize;

    FILE * f = fopen (sourceFile,"rb");
    Cypher = readFile(f,&fsize);
    data = (unsigned char *) calloc(fsize+10,sizeof(unsigned char));
    memset (data,0,fsize+10);
    unsigned char* key;
    f = fopen (keyFile,"rb");
    key = readFile(f,&ksize);
    if(ksize > 256)
    {
        printf("Key length can not be more than 256 byte according to the RC4 algorithm");
        exit(0);
    }
    
     //printing Cipher result on console to the user in HEX format
    printf("\n\nCipher from  %s: \n",sourceFile);
    for (int i = 0 ; i < fsize-1;i++)
    {
        printf("%02hhX  ",Cypher[i]);
    }
    printf("\n\n");
    
    //printing Key text on console
    printf("\nKey from %s:\n%s\n",keyFile, key);
    
    //Calling the RC4 function to do the decryption and return result in Cypher
    RC4(Cypher, fsize-1, key,ksize,data);
    
    //printing plain text on console
    printf("\n\nPlain Text written to  %s: \n%s\n\n",resultFile,data);

    /* Write data to the file */
    f = fopen(resultFile, "w");
    fwrite(data, 1, fsize, f);
    fclose(f);
    
    //release the pointers in memory
    free (data);
    free (Cypher);
    free(key);
}


int main(int argc, const char * argv[]){

    if(argc < 6){
        printf("Missing input, it has to be like this: \n");
        printf("\t gcc Encrypt ~/Desktop/plainText.txt ~/Desktop/key.txt ~/Desktop/Cipher.txt integer-key-len-for-test\n");
        printf("\t gcc Decrypt ~/Desktop/Cipher.txt ~/Desktop/key.txt ~/Desktop/plainText.txt integer-key-len-for-test\n");
        exit(0);
    }
    const char *choice = argv[1];
    const char *sourceFile = argv[2];
    const char *keyFile = argv[3];
    const char *resultFile = argv[4];
    const int keylen = atoi(argv[5]);

    
    if(strcmp(choice,"Encrypt") == 0){
        Encryptor(sourceFile, keyFile, resultFile, keylen);
    }
    else if(strcmp(choice,"Decrypt") == 0){
        Decryptor(sourceFile,keyFile,resultFile);
    }
    else{
        printf("usage has to be like :\n");
        printf("\t gcc Encrypt ~/Desktop/plainText.txt ~/Desktop/key.txt ~/Desktop/Cipher.txt integer-key-len-for-test\n");
        printf("\t gcc Decrypt ~/Desktop/Cipher.txt ~/Desktop/key.txt ~/Desktop/plainText.txt integer-key-len-for-test\n");
        exit(0);
    }
    
    
    exit(1);
 
}
