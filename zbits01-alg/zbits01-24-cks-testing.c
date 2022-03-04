/*
	Author : zerobits01
	Project: Applied Cryptology Course at AUT
	Teacher: Dr Sadeghian
	TA	   : Mr Faraji
	Description: Designing and Implementing a crypto algorithm
		with 96 bits input/key/output
		The idea is to use zbits01 and changing the key-scheduling algorithm! 
	# after each round i have to check some tests
*/

////////////////////////////// Do Includes ///////////////////////////////

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <unistd.h>
#include <inttypes.h>


/////////////////////////// Defining constants //////////////////////////

#define true 1
#define false 0
#define W 24 // input size 24*4 = 96bits
#define R 19 // Rounds
#define LW 5 // this is floor of log(24)
#define SIZE_S R*2+4 // states size

// modulus for the zbits01 operations
const long int mod = (long int)pow((double)2, (double)W);

// magic numbers for zbits01
#define Pw (0xB7E15163 % mod)
#define Qw (0x9E3779B9 % mod)

static const uint8_t sbox[256] = {
  //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 
};

static const uint8_t rsbox[256] = {
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d 
};

#define getSBoxValue(num) (sbox[(num)])
#define getSBoxInvert(num) (rsbox[(num)])


/////////////////////////// Defining glob vars /////////////////////////

FILE *input;
FILE *output;
int usage;//to indicate the usage of program
char inputfile[30];
char outputfile[30];

int i;
unsigned int text;

int r;
char text_type[20];
unsigned int t;
unsigned int u;
unsigned int temp;
unsigned int A,B,C,D;
unsigned int S[SIZE_S];

int b=0;//key size
int c=0;//L size
int keybit=0;//max is 256
	int CC;
int v;

unsigned int L[9];//make it full size+1, actually max used is 8
unsigned int key_A;
unsigned int key_B;
unsigned int key_i;
unsigned int key_j;

char keyword[30];

/////////////////////////// Defining functions /////////////////////////


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


void do_checks(int A, int B, int C, int D){

    int unperiod_flag = true;
    char new_str[97];
	int size = 12;

	int tmp = 0;
	for(int i=0; i < 24; i++){
		tmp = (D&(1<<(i%W)));
		// printf("tmp is %d, i is %d\n", tmp, i);
		if(tmp == false){
			new_str[i] = '0';
		}else{
			new_str[i] = '1';
		}
	}
	for(int i=24; i < 48; i++){
		tmp = (C&(1<<(i%W)));
		// printf("tmp is %d, i is %d\n", tmp, i);
		if(tmp == false){
			new_str[i] = '0';
		}else{
			new_str[i] = '1';
		}
	}
	for(int i=48; i < 72; i++){
		tmp = (B&(1<<(i%W)));
		// printf("tmp is %d, i is %d\n", tmp, i);
		if(tmp == false){
			new_str[i] = '0';
		}else{
			new_str[i] = '1';
		}
	}
	for(int i=72; i < 96; i++){
		tmp = (A&(1<<(i%W)));
		// printf("tmp is %d, i is %d\n", tmp, i);
		if(tmp == false){
			new_str[i] = '0';
		}else{
			new_str[i] = '1';
		}
	}

    new_str[96] = '\0';
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
    check_autocorr_cryptool_mode(new_str, 96);

}


int max(int num1, int num2){
	return ((num1>num2)?num1:num2);
}


unsigned int rotate_l(unsigned int x, unsigned int bit){
	// implementing rotate with two shifts and OR
	return (((x << bit) | (x >> (32-bit)))%mod);
}


unsigned int rotate_r(unsigned int x, unsigned int bit){
	// implementing rotate with two shifts and OR
	return (((x >> bit) | (x << (32-bit)))%mod);
}


void key_schedule(){
	/*************************
	 *      Key schedule     *
	**************************/

	S[0]=Pw;
	int qwpow2 = (Qw*Qw)%mod;
	for(i=1;i<SIZE_S;i++){
		// S[i]=(S[i-1]+Qw)%mod;
		
		if (i % 2 == 0){
			S[i]=(S[i-1]+Qw)%mod;
		}else{
			S[i]=(S[i-1]+(qwpow2))%mod;
		}
	}

	key_A=key_B=key_i=key_j=0;


	v=3*max(CC,SIZE_S);
	int lkj, ski;
	for (i=1;i<=v;i++){
		lkj = (L[key_j]*L[key_j]) % mod;
		ski = (S[key_i]*S[key_i]) % mod;
		
		key_A=S[key_i]=rotate_l((S[key_i]+key_A+key_B)%mod,3);
		key_B=L[key_j]=rotate_l((L[key_j]+key_A+key_B)%mod,(key_A+key_B)%mod);
		
		L[(key_i+key_j)%CC]=rotate_l((lkj+ski)%mod,(key_A+key_B)%mod);
		
		key_i=(key_i+1)%(SIZE_S);
		key_j=(key_j+1)%(CC);
		// if((key_i % 2) == 1){
		// }else{
		// 	key_j=(key_j+2)%(CC);
		// }
	}
	// for (i=1;i<=v;i++){
	// 	printf("%d-", S[i]);
	// }

}


int zbits01_function(int inp){
	int p1 = (inp&(0xff<<16)) >> 16;
	int p2 = (inp&(0xff<<8)) >> 8;
	int p3 = inp&0xff;
	int t1 = getSBoxValue(p1);
	int t2 = getSBoxValue(p2);
	int t3 = getSBoxValue(p3);
	int res = (t1<<16)|(t2<<8)|(t3);
	// printf("res for f %d is: %d\n", inp, res);
	return res;
}


void zbits01_enc(){
	/*************************
	 *      Encryption       *
	**************************/
	printf("before init perm: %d,%d,%d,%d\n",A,B,C,D);
	B=(B+S[0])%mod;
	D=(D+S[1])%mod;
	printf("after init perm: %d,%d,%d,%d\n",A,B,C,D);

	for(r=1;r<=R;r++){

		// t=rotate_l(((B*((2*B+1)%mod))%mod), LW);
		// u=rotate_l(((D*((2*D+1)%mod))%mod), LW);
		// A=(rotate_l((A^t)%mod,(u & 0x1f)%mod)+S[2*r])%mod;
		// C=(rotate_l((C^u)%mod,(t & 0x1f)%mod)+S[2*r+1])%mod;


		t=rotate_l(((B*((2*B+1)%mod))%mod), LW);
		u=rotate_l(((D*((2*D+1)%mod))%mod), LW);
		A=(rotate_l((A^t)%mod,(u & 0x1f)%mod)+S[2*r])%mod;
		C=(rotate_l((C^u)%mod,(t & 0x1f)%mod)+S[2*r+1])%mod;

		A = zbits01_function(A);
		C = zbits01_function(C);

		temp=A%mod;
		A=B%mod;
		B=C%mod;
		C=D%mod;
		D=temp%mod;
		printf("after round %d: %d,%d,%d,%d\n",r,A,B,C,D);
		// do_checks(A, B, C, D);
	}

	A=(A+S[2*R+2])%mod; // B of last round
	C=(C+S[2*R+3])%mod; // D of last round
	printf("after final perm: %d,%d,%d,%d\n",A,B,C,D);

}


int zbits01_rfunction(int inp){
	int p1 = (inp&(0xff<<16)) >> 16;
	int p2 = (inp&(0xff<<8)) >> 8;
	int p3 = inp&0xff;
	int t1 = getSBoxInvert(p1);
	int t2 = getSBoxInvert(p2);
	int t3 = getSBoxInvert(p3);
	int res = (t1<<16)|(t2<<8)|(t3);
	// printf("res for rf %d is: %d\n", inp, res);
	return res;
}


void zbits01_dec(){
	/*************************
	 *      Decryption       *
	**************************/
	printf("before dec-init perm: %d,%d,%d,%d\n",A,B,C,D);
	A=(A-S[2*R+2])%mod;
	C=(C-S[2*R+3])%mod;
	printf("after dec init-perm: %d,%d,%d,%d\n",A,B,C,D);

	for(r=R;r>=1;r--){
		temp=D%mod;
		D=C%mod;
		C=B%mod;
		B=A%mod;
		A=temp%mod;

		A = zbits01_rfunction(A);
		C = zbits01_rfunction(C);


		// u=rotate_l(((D*(((2*D+1)%mod)))%mod),LW);
		// t=rotate_l(((B*(((2*B+1)%mod)))%mod), LW);
		// C=(rotate_r((C-S[2*r+1])%mod, (t & 0x1f))^u);
		// A=(rotate_r((A-S[2*r])%mod, (u & 0x1f))^t);

		u=rotate_l(((D*(((2*D+1)%mod)))%mod),LW);
		t=rotate_l(((B*(((2*B+1)%mod)))%mod), LW);
		C=(rotate_r((C-S[2*r+1])%mod, (t & 0x1f))^u);
		A=(rotate_r((A-S[2*r])%mod, (u & 0x1f))^t);

		printf("after round %d of dec, %d,%d,%d,%d\n",r,A,B,C,D);

	}
	D=(D-S[1])%mod;
	B=(B-S[0])%mod;
	printf("after dec final-perm: %d,%d,%d,%d\n",A,B,C,D);

}


void read_input_and_init(){

	if (strcmp(keyword, "Encryption") == 0){
		usage = 0;
	}
	else if (strcmp(keyword, "Decryption") == 0){
		usage  = 1;
	}



	fscanf(input, "%s",  text_type);

	if(usage==0){
		if (strcmp(text_type, "plaintext:") != 0){
			printf("\nError, there should be \"plaintext:\" here in input file\n");
			fclose(input);
			exit(0);
		}
	}
	else{

		if (strcmp(text_type, "ciphertext:") != 0){
			printf("\nError, there should be \"ciphertext:\" here in input file\n");
			fclose(input);
			exit(0);
		}
	}

	// 4 * 24 = 96
	A=0x00000000; // 24 bits
	B=0x00000000;
	C=0x00000000;
	D=0x00000000;

	for(i=(W/8)-1;i>=0;i--){
		fscanf(input, "%x", &text);
		A=A|(text<<(i*8));
	}
	for(i=(W/8)-1;i>=0;i--){
		fscanf(input, "%x", &text);
		B=B|(text<<(i*8));
	}
	for(i=(W/8)-1;i>=0;i--){
		fscanf(input, "%x", &text);
		C=C|(text<<(i*8));
	}
	for(i=(W/8)-1;i>=0;i--){
		fscanf(input, "%x", &text);
		D=D|(text<<(i*8));
	}

	fscanf(input, "%s", text_type);

	if(usage==0){
		if (strcmp(text_type, "userkey:") != 0){
			printf("Cannot find out keyword \"userkey\", your format does not match.\n");
			fclose(input);
			exit(0);
		}/*end of if*/
	}else{

		if (strcmp(text_type, "userkey:") != 0){
			printf("Cannot find out keyword \"userkey\", your format does not match.\n");
			fclose(input);
			exit(0);
		}/*end of if*/
	}/*end of else*/


	for(i=0;i<9;i++){
		L[i]=0x00000000;
	}

	while ((fscanf(input, "%x", &text) == 1)&&(keybit<=256)){
		c=b/4;
		L[c]=(L[c]|(text<< (b%(W/8)* 8)));
		b++;
		keybit=keybit+8;
		printf("-> c is %d, b is %d, keybit is %d\n", c, b, keybit);
	}

	CC=c+1;
	if(keybit>256)
		printf("\n\nNotice, the input key exceeds 256bits\nbut this projects ignores the rest\n]n");
	else
		printf("\nKey size is %d\n\n",CC*32);

	fclose(input);

}


void write_output(){

	if(usage==0){
		fprintf(output, "ciphertext: ");
		printf("The ciphertext is:\n\n");

	}

	else{
		fprintf(output, "plaintext: ");
		printf( "The plaintext is:\n\n");

	}

	for (i=(W/8)-1;i>=0;i--){
		fprintf(output, "%.2x ", (A&(0xff<<(i*8))) >> (i*8));
		printf("%.2x ", (A&(0xff<<(i*8))) >> (i*8));
	}
	//fprintf(output, "\n");

	for (i=(W/8)-1;i>=0;i--){
		fprintf(output, "%.2x ", (B&(0xff<<(i*8))) >> (i*8));
		printf("%.2x ", (B&(0xff<<(i*8))) >> (i*8));

	}
	//fprintf(output, "\n");
	for (i=(W/8)-1;i>=0;i--){
		fprintf(output, "%.2x ", (C&(0xff<<(i*8))) >> (i*8));
		printf("%.2x ", (C&(0xff<<(i*8))) >> (i*8));

	}
	//fprintf(output, "\n");
	for (i=(W/8)-1;i>=0;i--){
		fprintf(output, "%.2x ", (D&(0xff<<(i*8))) >> (i*8));
		printf("%.2x ", (D&(0xff<<(i*8))) >> (i*8));

	}
	//fprintf(output, "\n");

	fclose(output);

}


/////////////////////////// MAIN Function /////////////////////////


int main(int argc, char** argv){


	printf("mod is %ld\n", mod);


	if (argc != 3){
		printf("\nWrong! There should be 3 arguments.\n");
		return 0;
	}


	if((input =fopen(argv[1],"r"))==NULL) {
		printf("\nFile Open Failed\n");
		return 0;

	}

	fscanf(input, "%s", keyword);

	read_input_and_init();

	key_schedule();

	if(usage==0){
		zbits01_enc();
	}/*end of if: usage==0*/
	else{
		zbits01_dec();
	}/*end of else, this is decryption*/

/**********************************************************
			output
**********************************************************/

	if((output=fopen(argv[2],"w"))==NULL) {
		printf("\nFailed to open output file\n");
		exit(-1);
	}


	write_output();
	
	printf("\n\nSucceed! The out put is also stored in %s\n\n",argv[2]);

	return 0;
}