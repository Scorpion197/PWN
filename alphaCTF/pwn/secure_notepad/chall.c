#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <sys/prctl.h>
#include "seccomp-bpf.h"

#define MAX_USERNAME 60
#define SECRET_TOKEN_LENGTH 8
#define NOTE_SIZE 100
#define TRUE 1 
#define FALSE 0
#define XOR_KEY 0xf

struct user {

    char *username; 
    char secret_token[SECRET_TOKEN_LENGTH];
    char *notes;
};

struct user *u; 
int maxusers = 0;

void disable_buffering();
void menu();
void login();
void logout();
int is_root();
int get_option(); 
void add_note();

static int install_syscall_filter(void);

int main(int argc, char *argv[]) {

    int option;

    disable_buffering();
    //seccomp_rules();

    while (1) {

        menu();
        option = get_option();

        switch(option) {

            case 1:

                login();
                break; 

            case 2:

                logout();
                break;

            case 3:


                if (is_root() == TRUE) {

                    add_note();
                } 
                
                else
                    printf("Nope\n");
                
                break;

            case 4:

                exit(0);
                break; 

            default:

                printf("invalid option\n");
                break;

        }
    }

}

void disable_buffering() {

    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

}

int get_option() {

    int option = 0;

    printf("enter an option: ");
    scanf("%d", &option);

    return option;

}
void menu() {

    printf("[1]- Login\n");
    printf("[2]- Logout\n");
    printf("[3]- Go to secret section\n");
    printf("[4]- Exit\n");

}


void login() {

    if (maxusers > 1) {

        printf("Only one user is allowed\n");
        return;
    }

    unsigned int username_len = 0;
    char *username = NULL;

    u = malloc(sizeof(struct user));
    printf("Enter your username length: ");

    scanf("%u", &username_len);
    getc(stdin);

    username = malloc(username_len);

    u->username = username;

    printf("username: ");

    if (fgets(username, username_len + 1, stdin) == NULL ) {

        printf("Failed getting username");
        exit(-1);

    }

    getc(stdin);
    char *end; 

    if ((end=strchr(username, '\n')) != NULL) {
        end[0] = '\0';
    }

    maxusers = maxusers + 1;
    printf("User added\n");

}

int is_root() {

    char temp_buffer[SECRET_TOKEN_LENGTH];
    
    memset(temp_buffer, 0, 8);

    if (maxusers != 0) {

        strcpy(temp_buffer, u->secret_token);    

        if (strcmp(temp_buffer, u->secret_token) == 0) 

            return TRUE;

    }   

    return FALSE;
}

void logout() {

    if (maxusers == 0) {

        printf("You should be signed in!\n");
        return;
    }


    char *user = u->username;

    free(u);
    free(user);

    maxusers--;
    
    printf("Logged out successfully\n");
}

void add_note() {

    char note_buffer[NOTE_SIZE];
    char  temp_buffer[48];

    memset(note_buffer, 0, NOTE_SIZE);
    memset(temp_buffer, 0, 48);

    puts("Add note: ");
    fflush(stdin);

    scanf("%100s", note_buffer);

    for (int i = 0; i < strlen(note_buffer); i++)
        note_buffer[i] = note_buffer[i] ^ XOR_KEY;

    strcpy(temp_buffer, note_buffer);
    printf(note_buffer);
    
    fflush(stdin);

}

static int install_syscall_filter(void)
{
	struct sock_filter filter[] = {
		/* Validate architecture. */
		VALIDATE_ARCHITECTURE,
		/* Grab the system call number. */
		EXAMINE_SYSCALL,
		/* List allowed syscalls. */
#ifdef __NR_sigreturn
		ALLOW_SYSCALL(sigreturn),
#endif
		ALLOW_SYSCALL(exit_group),
        ALLOW_SYSCALL(open),
		ALLOW_SYSCALL(exit),
		ALLOW_SYSCALL(read),
		ALLOW_SYSCALL(write),
		KILL_PROCESS,
	};
	struct sock_fprog prog = {
		.len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
		.filter = filter,
	};

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		perror("prctl(NO_NEW_PRIVS)");
		goto failed;
	}
	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
		perror("prctl(SECCOMP)");
		goto failed;
	}
	return 0;

failed:
	if (errno == EINVAL)
		fprintf(stderr, "SECCOMP_FILTER is not available. :(\n");
	return 1;
}
