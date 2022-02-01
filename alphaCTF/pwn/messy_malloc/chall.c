#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void disable_buffering();

int main(int argc, char *argv[]) {

    disable_buffering();

    size_t size; 
    void *pointer;

    printf("Welcome to messy malloc \n");
     
    printf("How much: "); 
    scanf("%ld", &size);

    pointer = malloc(size);
    printf("Allocated memory at: %p\n", pointer);

    printf("Where ?: ");
    scanf("%ld", &size);

    printf("Content: ");
    scanf("%zu",pointer + (size *8));

    printf("See ya ^^ \n");

    return 0;

}

void disable_buffering() {

    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}
