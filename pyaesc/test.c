#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#define TRUE  1
#define FALSE 0

static int randomized = FALSE;

void randomize(void)
{
  srand(time(NULL));
  randomized = TRUE;
}

/* returns a random number between base and max, inclusive */
int get_random(int base, int max)
{
  if (randomized == FALSE){
    randomize();
  }
  return rand() % (max - base + 1) + base;
}

void helloworld(){
	printf("HELLO WORLD\n");
}

void myprint(char *s){
	printf("%s\n", s);
}


int xorblock(char *x, char *y){
	//printf("%s^%s\n", x, y);
	for (int i = 0; i < 8; i++){
		x[i] = (char)(y[i] ^ x[i]);
		//printf("%02X ", x[i]);
	}
	//printf("\n");
	return 0;//x;
}