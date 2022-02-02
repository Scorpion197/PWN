#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define SIZE 100

void disable_buffering();

char shellcode[SIZE] = { '\0' };

int main(int argc, char *argv[]) {

    disable_buffering();
    printf("Enter shellcode and win a flag: ");

    scanf("%38s", shellcode);

    (*(void(*)()) shellcode)();

    return 0;
}


void disable_buffering() {

    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}