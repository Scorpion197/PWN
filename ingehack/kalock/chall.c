#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

void disable_buffering(); 

int main(int argc, char *argv[]) {

    disable_buffering();

    int *array = NULL, size =0, index = 0;

    printf("size: "); 
    scanf("%d", &size);

    if (size >= 0x100) 
        exit(1);

    array = calloc(size, sizeof(int));
    printf("index: ");
    scanf("%d", &index);

    printf("array[%d]: ", index);
    scanf("%d", &array[index]);
    puts("See you\n");

    return 0;
}

void disable_buffering() {

    setbuf(stdin, NULL);
    setbuf(stdout, NULL); 
    setbuf(stderr, NULL);
}
