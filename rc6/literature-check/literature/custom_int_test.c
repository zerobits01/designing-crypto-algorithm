#include <stdio.h>
#include <math.h>

#define W 24
#define mod (int)pow((double)2, (double)W)

struct IntCustom
{
    int val: W;
};

typedef struct IntCustom intc;

intc add(intc *first, intc *second){
    intc res;
	res.val = first->val + second->val;
	return res;
}

intc sub(intc *first, intc *second){
    intc res;
	res.val = first->val - second->val;
	return res;
}

intc mul(intc *first, intc *second){
    intc res;
	res.val = first->val * second->val;
	return res;
}

intc div(intc *first, intc *second){
    intc res;
	res.val = first->val / second->val;
	return res;
}

intc r_shift(intc *first, int count){
    intc res;
	res.val = first->val >> count;
	return res;
}

intc l_shift(intc *first, int count){
    intc res;
	res.val = first->val << count;
	return res;
}


// max is 16777215
int main(int argc, char argv[]){
    intc a;
    a.val = 16777218;
    intc b;
    b.val = 2;
    intc c;
    // c = add(&a, &b);
    printf("%d\n", add(&a, &b).val);
    c = sub(&a, &b);
    printf("%d\n", c.val);
    c = mul(&a, &b);
    printf("%d\n", c.val);
    c = div(&a, &b);
    printf("%d\n", c.val);
    printf("right shift by 2 %d\n", r_shift(&b, 2).val);
    printf("left shift by 2 %d\n", l_shift(&b, 2).val);
    printf("mod is %d\n", mod);
    printf("done\n");
    intc S[5];
    for(int i=0; i < 5; i++){
        S[i].val = i;
    }
    for(int i=0; i < 5; i++){
        printf("%d\n", S[i].val++);
    }
    for(int i=0; i < 5; i++){
        printf("%d\n", S[i].val);
    }

    return 0;
}