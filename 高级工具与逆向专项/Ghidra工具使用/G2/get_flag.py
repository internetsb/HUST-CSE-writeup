# g_raw内容
raw_hex = "9b b6 12 68 c1 f0 06 bc 9e a6 04 4d a6 91 11 4d 57 64 09 c4 e8 89 0a 80 5c 6c 10 d8 ad cb 05 82 b0 d3 0c 94 db be 19 b7 78 1a 07 99 4e 7c 1e e8 d5 f8 0d df 5f 3a 23 bc 59 74 17 e4 3d 05 14 56 c7 a1 1f 8c 7e 4f 16 e3 34 57 1d a8 ad 99 18 63 98 ae 0b 56 65 55 ff aa 61 55 ff aa b9 db 13 ac 69 5c 02 c7 f3 c6 20 de 64 55 ff aa 20 12 00 32 6c 0d 1b 94 53 37 01 8b 4e 2a 15 8d 2c 15 22 63 12 3f 08 59 16 22 0e 46 e4 81 03 6d 7e 47 0f d4 d4 e3 1a d6 89 eb 21 9a 02 32 1c 50"
raw = bytes.fromhex(raw_hex)

flag = [''] * 36

for off in range(0, len(raw), 4):
    b0, b1, b2, b3 = raw[off:off + 4]
    print(f"b0: {b0}, b1: {b1}, b2: {b2}, b3: {b3}")
    # index 必须小于 0x24
    if b2 >= 0x24:
        print(f"Invalid index: {b2}, skipping...")
        continue

    # 校验条件：b3 == (b0 + b1 + b2 + 5 * ((b0 + b1 + b2) // 0xfb)) & 0xff
    s = b0 + b1 + b2
    if b3 == ((s + 5 * (s // 0xfb)) & 0xff):
        flag[b2] = chr(b0 ^ b1)
    else:
        print(f"Invalid checksum for index {b2}: b3={b3}, expected={(s + 5 * (s // 0xfb)) & 0xff}")

content = ''.join(flag)
print(f"flag{{{content}}}")