#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>


#define MAX_USERNAME 60
#define SECRET_TOKEN_LENGTH 8


struct user {

    char *username; 
    char secret_token[SECRET_TOKEN_LENGTH];
    char *notes;
};

struct user *u; 
int maxusers = 0;

void disable_buffering();
void menu();
void secret_menu();
void login();
void logout();
int is_root();
int get_option(); 

int main(int argc, char *argv[]) {

    int option;

    disable_buffering();

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

                int root = 0;
                root = is_root();

                if (root == 1) {

                    secret_menu();
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
    printf("[3]- Get secret menu\n");
    printf("[4]- Exit\n");

}

void secret_menu() {

    printf("[1]- Add note\n");
    printf("[2]- View note\n");

    printf("> ");
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

    
    if (maxusers != 0) {

        printf("TOKEN : %s", u->secret_token);

        if (u->secret_token == "IS_ADMIN")

            //true
            return 1;
    }

    return 0;
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

