#include <stdio.h>
#include <string.h>
#include <stdlib.h> 
#include <unistd.h>

#define FLAG_FILE "flag.txt"
#define MAX_SIZE 50

void disable_buffering();

int main(int argc, char* argv[]) {

    disable_buffering();

    char flag_buffer[] = "flag{fake_flag_for_testing_real_one_is_on_the_server}";
    FILE *flag_fd = NULL;
    printf("Welcome ");
    flag_fd = fopen(FLAG_FILE, "w");

    if (flag_fd == NULL) {

        printf("Failed creating flag file");
        exit(0);
    }

    fprintf(flag_fd, "%s", flag_buffer);
    fclose(flag_fd);
    
    usleep(25000);
    system("rm flag.txt");
    printf("Ended");
    
    return 0;
}

void disable_buffering() {

    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

}
