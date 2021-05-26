#include<stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//gcc -o getenv getenv.c
int main(int argc, char *argv[]) {
   char *ptr;

   if(argc < 3) {
      fprintf(stderr, "Usage: %s <environment var> <target program name>\n", argv[0]);
      exit(1);
   }

   /* Get env var location. */
   ptr = getenv(argv[1]);

   /* Adjust for program name. */
   ptr += (strlen(argv[0]) - strlen(argv[2])) * 2;
   printf("%s will be at %p\n", argv[1], ptr);
}
