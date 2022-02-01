#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define MAX_LENGTH 2048

int main(int argc, char *argv[]) {

    setbuf(stdout, NULL);

    size_t size = 0;
    int *ptr = NULL;
    char buffer[MAX_LENGTH + 3];

    unsigned int content = 0;
    char line;


    printf("Welcome to messy malloc \n");
    printf("Give us a welcoming message: "); 

    fgets(buffer, MAX_LENGTH, stdin);
    printf("Thank you let's start now!\n");

    printf("How much: "); 
    scanf("%ld", &size);

    ptr = malloc(size);
    printf("Allocated memory at: %p\n", ptr);

    printf("Where ?: ");
    scanf("%ld", &size);

    printf("Content: ");
    
    scanf("%zu", (ptr + (size * 8)));

    printf("%s", buffer);


    return 0;

}

