
#include <signal.h>
#include <stdio.h>


int main(void) {
  raise(SIGUSR1);

  printf("In example_prog2.c!\n");
  return 0;
}
