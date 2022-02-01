#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void disable_buffering();

void main(int argc, char *argv[]) {

    disable_buffering();

    printf("Welcome to messy malloc \n");
    size_t size; 
    void *pointer; 

    printf("How much: "); 
    scanf("%ld", &size);

    pointer = malloc(size);
    printf("Allocated memory at: %p\n", pointer);

    printf("Where ?: ");
    scanf("%ld", &size);

    printf("Content: ");
    scanf("%zu",pointer + (size *8));

    exit(0);

}

void disable_buffering() {

    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}