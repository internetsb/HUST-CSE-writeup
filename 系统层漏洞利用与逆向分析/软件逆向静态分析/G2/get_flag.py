# KSA 初始化S盒
def InitSbox(k):
    # 初始化S盒 存初始值0-255
    S = list(range(256))
    T = [] # 用于轮转存放key
    for i in range(256):
        T.append(k[i % len(k)])  # 存放轮转的256位key
    j = 0
    for i in range(256):
        j = (j + S[i] + T[i]) % 256
        # 通过交换，打乱S盒
        S[i], S[j] = S[j], S[i]
    return S

# PRGA生成密钥流
def encrypt_or_decrypt(m, k):
    c = ""
    i = j = 0
    # 调用已经初始化的S盒
    S = InitSbox(k)
    for x in range(len(m)):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]  # 交换 打乱S盒
        t = (S[i] + S[j]) % 256
        # 将生成的密钥流key逐一与明文进行异或，格式化成16进制字符串
        c += '%02x' % (m[x] ^ S[t])
    return c

KEY = [0x2F, 0x9E, 0x4A, 0xC3, 0x71, 0x85, 0xD6, 0x1B] # 0x140004070前8字节
ENCRYPTED_FLAG = [0x20, 0xFF, 0xEA, 0xF6, 0xAE, 0x95, 0x1D, 0x9D, 0x5E, 0xF4, 0x48, 0xDA, 0xE6, 0xAB, 0x70, 0xA8, 0x90, 0xEA, 0xD9, 0x87, 0x47, 0x40, 0xDD, 0x0C, 0x25, 0x58, 0x13, 0x9D, 0x3A, 0xFF, 0xC4, 0x31, 0xD6, 0x86, 0xA3, 0x13, 0xCF, 0x12, 0x7F, 0x89, 0xF0, 0xEC] # 0x140004040前42字节

if __name__ == "__main__":
    decrypted_flag = encrypt_or_decrypt(ENCRYPTED_FLAG, KEY)
    print(bytes.fromhex(decrypted_flag).decode())