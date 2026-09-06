import struct

# 还原 Feistel 结构
cipher=bytes.fromhex('6f 6b 47 8f 17 bc d8 a0 bb 4a 2b c6 26 13 43 34 39 3f 4e bc 11 05 69 d6 15 90 e1 1d 25 aa 7b 9d')
A=0x9E3779B9
B=0x21524111
MASK=0xffffffff
def F(x): 
    return (A*x-B)&MASK
out=bytearray()
for i in range(0,32,8):
    lp,rp=struct.unpack_from('<II',cipher,i)
    r=rp ^ F(lp)
    l=lp ^ F(r)
    out += struct.pack('<II',l,r)
print(out.decode())

# 恢复flag
mask=0x10842000
print("'-'位置：")
print([i for i in range(5,29) if (mask>>i)&1])

s=out.decode()
# 添加-
j=0; chars=[]
for pos in range(5,41):
    if (mask>>pos)&1:
        chars.append('-')
    else:
        chars.append(s[j]); j+=1
print("最终flag：")
print('flag{'+''.join(chars)+'}')