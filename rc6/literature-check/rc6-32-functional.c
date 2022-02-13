/*
	Author : zerobits01
	Project: Applied Cryptology Course at AUT
	Teacher: Dr Sadeghian
	TA	   : Mr Faraji
	Description: Designing and Implementing a crypto algorithm
		with 96 bits input/key/output
		The idea is to use RC6 and changing the key-scheduling algorithm! 
	# after each round i have to check some tests
*/

////////////////////////////// Do Includes ///////////////////////////////

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>

/////////////////////////// Defining constants //////////////////////////

#define W 32 // input size 24*4 = 96bits
#define R 16 // Rounds
#define LW 5 // this is floor of log(24)
#define SIZE_S R*2+4 // states size

// modulus for the RC6 operations
const long int mod = (long int)pow((double)2, (double)W);

// magic numbers for RC6
#define Pw (0xB7E15163 % mod)
#define Qw (0x9E3779B9 % mod)

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

	for(i=1;i<SIZE_S;i++){
		S[i]=(S[i-1]+Qw)%mod;
	}

	key_A=key_B=key_i=key_j=0;


	v=3*max(CC,SIZE_S);
	for (i=1;i<=v;i++){

		key_A=S[key_i]=rotate_l((S[key_i]+key_A+key_B)%mod,3);
		key_B=L[key_j]=rotate_l((L[key_j]+key_A+key_B)%mod,(key_A+key_B)%mod);
		key_i=(key_i+1)%(SIZE_S);
		key_j=(key_j+1)%(CC);
	}
	for (i=1;i<=v;i++){
		printf("%d-", S[i]);
	}

}


void zbits01_enc(){
	/*************************
	 *      Encryption       *
	**************************/
	B=(B+S[0])%mod;
	D=(D+S[1])%mod;

	for(r=1;r<=R;r++){

		t=rotate_l(((B*((2*B+1)%mod))%mod), LW);
		u=rotate_l(((D*((2*D+1)%mod))%mod), LW);
		A=(rotate_l((A^t)%mod,(u & 0x1f)%mod)+S[2*r])%mod;
		C=(rotate_l((C^u)%mod,(t & 0x1f)%mod)+S[2*r+1])%mod;
		temp=A%mod;
		A=B%mod;
		B=C%mod;
		C=D%mod;
		D=temp%mod;
	}

	A=(A+S[2*R+2])%mod;
	C=(C+S[2*R+3])%mod;
}


void zbits01_dec(){
	/*************************
	 *      Decryption       *
	**************************/
	C=(C-S[2*R+3])%mod;
	A=(A-S[2*R+2])%mod;

	for(r=R;r>=1;r--){
		temp=D%mod;
		D=C%mod;
		C=B%mod;
		B=A%mod;
		A=temp%mod;

		u=rotate_l((D*(((2*D+1)%mod)))%mod,LW);
		t=rotate_l((B*((2*B+1)%mod))%mod, LW);
		C=(rotate_r((C-S[2*r+1])%mod, (t & 0x1f))^u);
		A=(rotate_r((A-S[2*r])%mod, (u & 0x1f))^t);
	}
	D=(D-S[1])%mod;
	B=(B-S[0])%mod;

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

	A=0x00000000;
	B=0x00000000;
	C=0x00000000;
	D=0x00000000;

	for(i=0;i<(W/8);i++){
		fscanf(input, "%x", &text);
		A=A|(text<<(i*8));
	}
	for(i=0;i<(W/8);i++){
		fscanf(input, "%x", &text);
		B=B|(text<<(i*8));
	}
	for(i=0;i<(W/8);i++){
		fscanf(input, "%x", &text);
		C=C|(text<<(i*8));
	}
	for (i=0;i<(W/8);i++){
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
	}

	else{

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

	for (i=0;i<(W/8);i++){
		fprintf(output, "%.2x ", (A&(0xff<<(i*8))) >> (i*8));
		printf("%.2x ", (A&(0xff<<(i*8))) >> (i*8));
	}
	//fprintf(output, "\n");

	for (i=0;i<(W/8);i++){
		fprintf(output, "%.2x ", (B&(0xff<<(i*8))) >> (i*8));
		printf("%.2x ", (B&(0xff<<(i*8))) >> (i*8));

	}
	//fprintf(output, "\n");
	for (i=0;i<(W/8);i++){
		fprintf(output, "%.2x ", (C&(0xff<<(i*8))) >> (i*8));
		printf("%.2x ", (C&(0xff<<(i*8))) >> (i*8));

	}
	//fprintf(output, "\n");
	for (i=0;i<(W/8);i++){
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