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

#define W 24 // W*4 gonna be the bit size of block
#define R 12  // rounds count
#define LW 4 // rotation size
#define SIZE_S R*2+4 // State size for key shedule
#define Pw 0xB7E151 // magic values in rc6
#define Qw 0x9E3779 // magic values in rc6

const long int mod = (long int)pow((double)2, (double)W);

/////////////////////////// Defining types and OPs /////////////////////////

struct UnsignedIntCustom{
    unsigned int val: W;
};

typedef struct UnsignedIntCustom intc;

intc add(intc first, intc second){
    intc res;
	res.val = (first.val + second.val)%mod;
	return res;
}

intc sub(intc first, intc second){
    intc res;
	res.val = (first.val - second.val)%mod;
	return res;
}

intc mul(intc first, intc second){
    intc res;
	res.val = (first.val * second.val)%mod;
	return res;
}

intc div(intc first, intc second){
    intc res;
	res.val = (first.val / second.val)%mod;
	return res;
}

intc r_shift(intc first, int count){
    intc res;
	res.val = (first.val >> count)%mod;
	return res;
}

intc l_shift(intc first, int count){
    intc res;
	res.val = (first.val << count)%mod;
	return res;
}

intc rotate_l(intc x, int bit){
	// implementing rotate with two shifts and OR
    intc res;
	res.val = (((x.val << bit)%mod) | ((x.val >> (W-bit))%mod)); 
	return res;
}

intc rotate_r(intc x, int bit){
	// implementing rotate with two shifts and OR
    intc res;
	res.val = (((x.val >> bit)%mod) | ((x.val << (W-bit))%mod));
	return res;
}

/////////////////////////// Defining glob vars /////////////////////////


FILE *input; // input file
FILE *output; // output file
intc usage; //to indicate the usage of program(should 0=enc or 1=dec)


intc i; // used in some for-loops 
unsigned int text; // reading text from file

intc r; // rounds
char text_type[20]; // saving plaintext/ciphertext to check
// used in some loops
intc t;
intc u;
intc temp;

intc A,B,C,D; // RC6 uses type 2 fiestel so it divides input into 4 registers
intc S[SIZE_S]; // States

intc b = {0}; //key size in byte
intc c = {0}; //L size

intc keybit={0}; //max is 256
intc CC;
intc v;

intc L[9];  //make it full size+1, actually max used is 8
intc key_A; // these are for key scheduling temps
intc key_B;
intc key_i;
intc key_j;

intc int24_1 = {1};
intc int24_2 = {2};
intc int24_3 = {3};
intc int24_R = {R};

char keyword[30]; // for reading the Enc Dec from file and check the usage


/////////////////////////// Defining functions /////////////////////////


int max(intc num1, intc num2){
	return ((num1.val>num2.val)?num1.val:num2.val);
}


void key_schedule(){
	S[0].val=Pw;
	intc qw = {Qw};
	for(i.val=1;i.val<SIZE_S;i.val++){
		S[i.val].val = add(S[i.val-1], qw).val;
	}

	key_A.val = key_B.val = key_i.val = key_j.val = 0;
	intc st = {SIZE_S};
	v.val = 3*max(CC,st);
	for (i.val=1;i.val<=v.val;i.val++){

		intc sum1 = add(S[key_i.val], key_A);
		sum1 = add(sum1, key_B);
		intc trl1 = rotate_l(sum1,3);
		key_A.val = S[key_i.val].val = trl1.val;

		intc sum2 = add(L[key_j.val], key_A);
		sum2 = add(sum2, key_B);
		intc trl2 = rotate_l(sum2, add(key_A, key_B).val);
		key_B.val = L[key_j.val].val = trl2.val;


		key_i.val = (key_i.val+1)%(SIZE_S);
		key_j.val = (key_j.val+1)%(CC.val);
	}

}


void zbits_encrypt(){
	B = add(B, S[0]);
	D = add(D, S[1]);

	for(r.val=1; r.val<=R; r.val++){

		t = rotate_l(mul(B,(add(mul(int24_2, B), int24_1))), LW);
		u = rotate_l(mul(D,(add(mul(int24_2, D), int24_1))), LW);
		
		intc anded_At = {A.val^t.val};
		intc anded_u0x1f = {u.val & 0x1f};
		A = add(rotate_l(anded_At, anded_u0x1f.val), S[mul(int24_2, r).val]);
		
		intc anded_Cu = {C.val^u.val};
		intc anded_t0x1f = {t.val & 0x1f};
		C = add(rotate_l(anded_Cu, anded_t0x1f.val), S[add(mul(int24_2, r), int24_1).val]);
		
		temp=A;
		A=B;
		B=C;
		C=D;
		D=temp;
	}

	A = add(A, S[add(mul(int24_2, int24_R),int24_2).val]);
	C = add(C, S[add(mul(int24_2, int24_R),int24_3).val]);
}


void zbits_decrypt(){
	A = sub(A, S[add(mul(int24_2, int24_R),int24_2).val]);
	C = sub(C, S[add(mul(int24_2, int24_R),int24_3).val]);

	for(r.val=R; r.val>=1; r.val--){
		temp=D;
		D=C;
		C=B;
		B=A;
		A=temp;
		
		u = rotate_l(mul(D,(add(mul(int24_2, D), int24_1))), LW);
		t = rotate_l(mul(B,(add(mul(int24_2, B), int24_1))), LW);
		
		intc anded_t0x1f = {t.val & 0x1f};
		intc anded_u0x1f = {u.val & 0x1f};
		
		C.val = (rotate_r(sub(C, S[add(mul(int24_2, r), int24_1).val]), anded_t0x1f.val).val ^ u.val);
		A.val = (rotate_r(sub(A,S[mul(int24_2, r).val]), anded_u0x1f.val).val ^ t.val);
	
	}

	B = sub(B, S[0]);
	D = sub(D, S[1]);
}


/////////////////////////// MAIN Function /////////////////////////


int main(int argc, char** argv){

	if (argc != 3){
		printf("\nWrong! There should be 3 arguments.\n");
		return 0;
	}

	// argv1 is input file
	if((input =fopen(argv[1],"r"))==NULL) {
		printf("\nFile Open Failed\n");
		return 0;
	}

	// reading input
	fscanf(input, "%s", keyword);


	// check if its enc or dec based on input file first line
	if (strcmp(keyword, "Encryption") == 0){
		usage.val = 0; // usage 0 for enc
	}
	else if (strcmp(keyword, "Decryption") == 0){
		usage.val  = 1; // usage 1 for dec
	}

	// check text file if its 
	fscanf(input, "%s",  text_type);


	// if its enc the text type should be plain else it should break
	if(usage.val==0){
		if (strcmp(text_type, "plaintext:") != 0){
			printf("\nError, there should be \"plaintext:\" here in input file\n");
			fclose(input);
			return 0;
		}
	}
	else{

		if (strcmp(text_type, "ciphertext:") != 0){
			printf("\nError, there should be \"ciphertext:\" here in input file\n");
			fclose(input);
			return 0;
		}
	}

	// Basic initialization
	A.val=0x000000; // 24bit values of 0 as initial value
	B.val=0x000000;
	C.val=0x000000;
	D.val=0x000000;

	for(i.val=0;i.val<(W/8);i.val++){
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

	// reading the key for enc/dec
	if(usage==0){
		if (strcmp(text_type, "userkey:") != 0){
			printf("Cannot find out keyword \"userkey\", your format does not match.\n");
			fclose(input);
			return 0;
		}
	}

	else{

		if (strcmp(text_type, "userkey:") != 0){
			printf("Cannot find out keyword \"userkey\", your format does not match.\n");
			fclose(input);
			return 0;
		}
	}


	for(i=0;i<9;i++){

		L[i]=0x000000;

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


	// TODO: check the Enc/Dec time here

	/*************************
	 *      KeySchedule      *
	**************************/


	key_schedule();

	/*************************
	 *      Encryption       *
	**************************/
	if(usage==0){
		zbits_encrypt();

	}/*end of if: usage==0*/

	/*************************
	 *      Decryption       *
	**************************/
	else{
		zbits_decrypt();
	}/*end of else, this is decryption*/


	// TODO: check the Enc/Dec time here


/**********************************************************
			write output
**********************************************************/

	if((output=fopen(argv[2],"w"))==NULL) {
		printf("\nFailed to open output file\n");
		exit(-1);
	}

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

	printf("\n\nSucceed! The out put is also stored in %s\n\n",argv[2]);

	return 0;
}
