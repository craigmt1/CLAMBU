#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>

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