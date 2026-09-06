# 高级工具与逆向专项-Ghidra工具使用-G1 WriteUp

Ghidra 是美国国家安全局（NSA）开源的逆向工程框架，能够对二进制可执行文件进行反汇编和反编译，将机器码还原为接近 C 语言的伪代码，是 CTF 逆向类题目中最常用的静态分析工具之一。本题要求使用 Ghidra 对一个 ELF 可执行文件进行分析，理解其校验逻辑并逆向求出 flag。下面从 Ghidra 的基本操作开始，逐步记录完整的解题过程。

**启动 Ghidra 并创建项目。** 打开 Ghidra 后，首先看到的是项目管理窗口。此时标题栏显示 "Ghidra: NO ACTIVE PROJECT"，表示当前没有打开任何项目，中间的文件区域也是空白的。Ghidra 的所有分析工作都必须在一个项目中进行，因此第一步是创建一个新项目。

![启动界面](https://k13in-images.oss-cn-wuhan-lr.aliyuncs.com/Snipaste_2026-08-24_15-19-53.png)

点击菜单栏的 **File → New Project...**，启动新建项目向导。

![新建项目菜单](https://k13in-images.oss-cn-wuhan-lr.aliyuncs.com/Snipaste_2026-08-24_15-21-30.png)

在弹出的 "New Project" 对话框中，选择项目类型为 **Non-Shared Project**（非共享项目，适用于个人本地分析），然后点击 **Next >>** 进入下一步。

![选择项目类型](https://k13in-images.oss-cn-wuhan-lr.aliyuncs.com/Snipaste_2026-08-24_15-22-00.png)

接下来设置项目的存储位置和名称。在 Project Directory 中选择一个目录路径，在 Project Name 中填写项目名称（这里填写 "demo"），然后点击 **Finish** 完成项目创建。

![image-20260824153937540](https://k13in-images.oss-cn-wuhan-lr.aliyuncs.com/image-20260824153937540.png)

项目创建成功后，主窗口标题变为 "Ghidra: demo"，Active Project 区域显示了 demo 文件夹，Tool Chest（工具箱）中也出现了几个可用工具的图标（绿色龙图标是 CodeBrowser，即主分析工具）。底部状态栏提示 "Creating project: /Users/k13in/GhidraProject/demo"。

![image-20260824154040024](https://k13in-images.oss-cn-wuhan-lr.aliyuncs.com/image-20260824154040024.png)

**导入待分析的二进制文件。** 点击菜单栏的 **File → Import File...**（快捷键 I），准备将题目附件 `challenge.elf` 导入到项目中。

![image-20260824154140981](https://k13in-images.oss-cn-wuhan-lr.aliyuncs.com/image-20260824154140981.png)

在文件选择对话框中，导航到 challenge.elf 所在的目录，选中该文件后点击 **Select File To Import**。

![选择文件](https://k13in-images.oss-cn-wuhan-lr.aliyuncs.com/Snipaste_2026-08-24_15-24-56.png)

Ghidra 会自动识别文件格式。在 Import 对话框中可以看到，Format 被自动识别为 "Executable and Linking Format (ELF)"，Language 被识别为 "x86:LE:64:default:gcc"，说明这是一个 x86-64 架构、小端序、由 GCC 编译的 ELF 可执行文件。确认信息无误后点击 **OK**。

![image-20260824154246519](https://k13in-images.oss-cn-wuhan-lr.aliyuncs.com/image-20260824154246519.png)

导入完成后弹出 Import Results Summary 窗口，展示了文件的详细元信息：Language ID 为 x86:LE:64:default、Compiler ID 为 gcc、共 8292 字节、30 个函数、67 个符号，源文件名为 challenge.c，使用 GCC (Debian 15.2.0-17) 编译。确认后点击 **OK** 关闭。

![导入结果摘要](https://k13in-images.oss-cn-wuhan-lr.aliyuncs.com/Snipaste_2026-08-24_15-25-40.png)

回到项目窗口，可以看到 demo 文件夹下已经出现了 `challenge.elf` 文件。此时双击该文件，即可在 CodeBrowser 中打开它进行分析。

![image-20260824154411619](https://k13in-images.oss-cn-wuhan-lr.aliyuncs.com/image-20260824154411619.png)

**执行自动分析。** CodeBrowser 打开文件后，会弹出 "Analyze?" 对话框，询问是否要对程序进行自动分析。点击 **Yes** 进入分析选项配置。

![分析提示](https://k13in-images.oss-cn-wuhan-lr.aliyuncs.com/Snipaste_2026-08-24_15-28-51.png)

在 Analysis Options 对话框中，列出了 Ghidra 提供的所有分析器（Analyzer）。默认配置已经勾选了大部分常用分析器，包括 ASCII Strings（字符串识别）、Data Reference（数据引用分析）、Decompiler Parameter ID（反编译参数识别）、Decompiler Switch Analysis（switch 语句分析）、Demangler GNU（C++ 符号解修饰）等。对于本题保持默认配置即可，直接点击 **Analyze** 开始自动分析。

![分析选项](https://k13in-images.oss-cn-wuhan-lr.aliyuncs.com/Snipaste_2026-08-24_15-29-04.png)

**认识 CodeBrowser 主界面。** 分析完成后，CodeBrowser 进入主工作界面，这是 Ghidra 中最核心的分析环境。整个界面分为以下几个区域：

![CodeBrowser 主界面](https://k13in-images.oss-cn-wuhan-lr.aliyuncs.com/Snipaste_2026-08-24_15-30-04.png)

界面左上角是 **Program Trees**（程序树）面板，以树状结构展示了 ELF 文件的各个段（Section），例如 .text（代码段）、.data（已初始化数据段）、.bss（未初始化数据段）、.rodata（只读数据段）、.got.plt（全局偏移表）等，点击某个段名可以快速跳转到对应的内存区域。

左侧中间是 **Symbol Tree**（符号树）面板，按类别组织了程序中的所有符号信息，包括 Imports（导入函数，如 printf、strlen 等 libc 函数）、Exports（导出符号）、Functions（程序自身定义的函数列表）、Labels（标签）、Classes（类）和 Namespaces（命名空间）。展开 Functions 节点就能看到程序中所有被识别出的函数，这是定位关键逻辑的主要入口。

左下角是 **Data Type Manager**（数据类型管理器），管理程序中使用的所有数据类型定义，包括内置类型（BuiltInTypes）、从当前程序中识别出的结构体和类型，以及通用 C 库类型（generic_clib_64）。

界面中央是 **Listing**（反汇编列表）窗口，这是最大的面板，显示程序的反汇编代码，左侧是内存地址和原始字节，右侧是对应的汇编指令，同时标注了交叉引用信息（XREF），可以看到哪些地方调用或引用了当前位置。

界面右侧是 **Decompiler**（反编译器）窗口，当在 Listing 窗口或 Symbol Tree 中选中某个函数时，这里会自动显示该函数的反编译伪代码，这是最接近源代码的高层表示，也是逆向分析中最常阅读的区域。

界面底部是 **Console - Scripting**（控制台与脚本）面板，用于查看分析日志输出和运行 Ghidra 脚本。

**定位并分析 main 函数。** 在 Symbol Tree 面板中展开 Functions 节点，找到 main 函数并点击，右侧 Decompiler 窗口立即显示出 main 函数的反编译伪代码。Ghidra 反编译得到的完整伪代码如下：

```c
undefined8 main(void)
{
  int iVar1;
  char *pcVar2;
  undefined8 uVar3;
  size_t sVar4;
  uchar *in_RCX;
  size_t siglen;
  uchar *sig;
  size_t in_R8;
  undefined8 local_48;
  undefined8 local_40;
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  undefined8 local_20;
  undefined8 local_18;
  undefined8 local_10;

  local_48 = 0;
  local_40 = 0;
  local_38 = 0;
  local_30 = 0;
  local_28 = 0;
  local_20 = 0;
  local_18 = 0;
  local_10 = 0;
  printf("Enter flag: ");
  pcVar2 = fgets((char *)&local_48,0x40,stdin);
  uVar3 = 1;
  if (pcVar2 != (char *)0x0) {
    sig = "\n";
    sVar4 = strcspn((char *)&local_48,"\n");
    *(undefined1 *)((long)&local_48 + sVar4) = 0;
    quick_check(&local_48);
    iVar1 = verify((EVP_PKEY_CTX *)&local_48,sig,siglen,in_RCX,in_R8);
    if (iVar1 == 0) {
      puts("Wrong.");
      uVar3 = 1;
    }
    else {
      puts("Correct!");
      uVar3 = 0;
    }
  }
  return uVar3;
}
```

这段伪代码中有不少 Ghidra 自动推断的类型名（如 `undefined8`、`EVP_PKEY_CTX *`）看起来比较混乱，将其还原为人类易读的代码后逻辑就非常清晰了：

```c
int main(void) {
    char input[64] = {0};

    printf("Enter flag: ");
    if (fgets(input, 0x40, stdin) == NULL)
        return 1;

    // 去掉末尾换行符
    input[strcspn(input, "\n")] = '\0';

    quick_check(input);

    if (verify(input)) {
        puts("Correct!");
        return 0;
    } else {
        puts("Wrong.");
        return 1;
    }
}
```

程序的流程很简单：读取用户输入，去掉换行符，调用 `quick_check` 做初步检查，然后调用 `verify` 进行完整校验，返回非零表示正确。

**分析 `quick_check` 函数。** 展开 Symbol Tree 中的 Functions 节点，点击 `quick_check` 函数，Ghidra 反编译得到的伪代码如下：

![image.png](https://k13in-images.oss-cn-wuhan-lr.aliyuncs.com/20260824155031711.png)

```c
void quick_check(char *param_1)
{
  int iVar1;

  iVar1 = strncmp(param_1,"flag{",5);
  if (iVar1 == 0) {
    puts("[OK] Warm up done");
  }
  return;
}
```

还原为易读代码：

```c
void quick_check(char *input) {
    if (strncmp(input, "flag{", 5) == 0)
        puts("[OK] Warm up done");
}
```

这个函数仅做了一个简单的前缀检查——如果输入以 `"flag{"` 开头就打印提示信息，不影响最终校验结果。真正的校验逻辑在 verify 函数中。

**分析 verify 函数。** 这是整道题的核心。Ghidra 反编译得到的完整伪代码如下：

```c
int verify(EVP_PKEY_CTX *ctx,uchar *sig,size_t siglen,uchar *tbs,size_t tbslen)
{
  int iVar1;
  int iVar2;
  uint uVar3;
  size_t sVar4;
  ulong uVar5;
  long lVar6;
  uint uVar7;
  undefined1 local_68 [32];
  EVP_PKEY_CTX local_48 [32];
  undefined1 local_28;

  sVar4 = strlen((char *)ctx);
  uVar3 = 0;
  if (sVar4 == 0x2a) {
    iVar2 = strncmp((char *)ctx,"flag{",5);
    if (iVar2 == 0) {
      uVar3 = 0;
      if (ctx[0x29] == (EVP_PKEY_CTX)0x7d) {
        uVar5 = 5;
        iVar2 = 0;
        do {
          for (; ((uint)uVar5 < 0x1d && ((0x10842000UL >> (uVar5 & 0x3f) & 1) != 0));
              uVar5 = uVar5 + 1) {
            if (ctx[uVar5] != (EVP_PKEY_CTX)0x2d) {
              return 0;
            }
          }
          uVar7 = (byte)ctx[uVar5] - 0x30;
          if (0x36 < (byte)uVar7) {
            return 0;
          }
          if ((0x7e0000007e03ffU >> ((ulong)uVar7 & 0x3f) & 1) == 0) {
            return 0;
          }
          iVar1 = iVar2 + 1;
          local_48[iVar2] = ctx[uVar5];
          uVar5 = uVar5 + 1;
          iVar2 = iVar1;
        } while (uVar5 != 0x29);
        if (iVar1 == 0x20) {
          local_28 = 0;
          lVar6 = 0;
          do {
            feistel_enc_block(local_48 + lVar6,local_68 + lVar6);
            lVar6 = lVar6 + 8;
          } while (lVar6 != 0x20);
          iVar2 = memcmp(local_68,g_cipher,0x20);
          uVar3 = (uint)(iVar2 == 0);
        }
      }
    }
    else {
      uVar3 = 0;
    }
  }
  return uVar3;
}
```

经过仔细阅读和整理，还原为易读代码：

```c
int verify(char *input) {
    // 1) 总长度必须是 42（0x2a）
    if (strlen(input) != 42) return 0;

    // 2) 必须以 "flag{" 开头
    if (strncmp(input, "flag{", 5) != 0) return 0;

    // 3) 最后一个字符必须是 '}'（0x7d），即 input[41]
    if (input[41] != '}') return 0;

    // 4) 遍历 input[5] 到 input[40]，提取有效字符
    //    位掩码 0x10842000 指定了哪些位置必须是 '-'（0x2d）
    //    其余位置必须是合法的十六进制字符 [0-9a-f]
    char extracted[33];
    int idx = 0;
    for (int pos = 5; pos < 41; pos++) {
        // 如果当前位置在掩码中被标记，则必须是 '-'
        if (pos < 29 && ((0x10842000UL >> pos) & 1)) {
            if (input[pos] != '-') return 0;
            continue;
        }
        // 否则必须是合法的十六进制字符
        // ...（字符范围检查）
        extracted[idx++] = input[pos];
    }

    // 5) 提取出的有效字符必须恰好 32 个
    if (idx != 32) return 0;
    extracted[32] = '\0';

    // 6) 对提取出的 32 字节分 4 块，每块 8 字节，做 Feistel 加密
    char cipher_out[32];
    for (int i = 0; i < 32; i += 8)
        feistel_enc_block(extracted + i, cipher_out + i);

    // 7) 加密结果与全局数组 g_cipher 比较
    return memcmp(cipher_out, g_cipher, 32) == 0;
}
```

通过分析位掩码 `0x10842000`，可以确定横杠 `-` 出现的位置。将 `0x10842000` 转为二进制后，第 13、18、23、28 位为 1，对应 flag 中横杠的位置。这说明 flag 的内部格式是 `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`，即标准的 UUID 格式。去掉横杠后恰好 32 个字符，经过 Feistel 加密后与硬编码的密文 `g_cipher` 进行比较。

**分析加密函数 F 和 feistel_enc_block。** Ghidra 反编译得到的伪代码如下：

```c
int F(int param_1)
{
  return param_1 * -0x61c88647 + -0x21524111;
}

void feistel_enc_block(uint *param_1,uint *param_2)
{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;

  uVar1 = *param_1;
  uVar2 = param_1[1];
  uVar3 = F(uVar2);
  uVar4 = F(uVar1 ^ uVar3);
  *param_2 = uVar1 ^ uVar3;
  param_2[1] = uVar4 ^ uVar2;
  return;
}
```

还原为易读代码：

```c
uint32_t F(uint32_t x) {
    return x * 0x9E3779B9 + 0xDEADBEEF;  // 黄金比例常数与经典魔数
}

void feistel_enc_block(uint32_t *in, uint32_t *out) {
    uint32_t L = in[0], R = in[1];
    uint32_t new_L = L ^ F(R);
    uint32_t new_R = F(new_L) ^ R;
    out[0] = new_L;
    out[1] = new_R;
}
```

这里 `-0x61c88647` 在 32 位无符号运算下等于 `0x9E3779B9`（黄金比例相关常数），`-0x21524111` 等于 `0xDEADBEEF`（经典调试魔数）。加密结构是一个 2 轮 Feistel 网络，每次处理 8 字节（两个 uint32），整个加密过程分 4 个块处理 32 字节数据。

**提取密文数据 `g_cipher`。** 在 Ghidra 的 Symbol Tree 中的 Lables 节点下找到全局变量 `g_cipher`，双击跳转到其在 Listing 窗口中的位置（地址 `0x00102040`），可以读取到 32 字节的密文数据：`6f 6b 47 8f 17 bc d8 a0 bb 4a 2b c6 26 13 43 34 39 3f 4e bc 11 05 69 d6 15 90 e1 1d 25 aa 7b 9d`。

![image.png](https://k13in-images.oss-cn-wuhan-lr.aliyuncs.com/20260824155223568.png)

**逆向 Feistel 加密恢复明文。** Feistel 网络的核心特性是加密过程可逆。已知加密过程为 `new_L = L ^ F(R)` 和 `new_R = F(new_L) ^ R`，那么解密时只需反推：先由 `new_L` 计算 `R = F(new_L) ^ new_R`，再由 `R` 计算 `L = new_L ^ F(R)`。编写 Python 解题脚本如下：

```python
import struct

def F(x):
    return ((x * 0x9E3779B9) + 0xDEADBEEF) & 0xFFFFFFFF

def feistel_decrypt_block(cipher_block):
    new_L, new_R = struct.unpack('<II', cipher_block)
    R = F(new_L) ^ new_R
    L = new_L ^ F(R)
    return struct.pack('<II', L, R)

g_cipher = bytes([
    0x6f, 0x6b, 0x47, 0x8f, 0x17, 0xbc, 0xd8, 0xa0,
    0xbb, 0x4a, 0x2b, 0xc6, 0x26, 0x13, 0x43, 0x34,
    0x39, 0x3f, 0x4e, 0xbc, 0x11, 0x05, 0x69, 0xd6,
    0x15, 0x90, 0xe1, 0x1d, 0x25, 0xaa, 0x7b, 0x9d,
])

plaintext = b''
for i in range(0, 32, 8):
    plaintext += feistel_decrypt_block(g_cipher[i:i+8])

inner = plaintext.decode()

dash_positions = {13, 18, 23, 28}
flag = list('flag{' + ' ' * 36 + '}')
idx = 0
for pos in range(5, 41):
    if pos in dash_positions:
        flag[pos] = '-'
    else:
        flag[pos] = inner[idx]
        idx += 1

flag = ''.join(flag)
print(f'[+] Flag: {flag}')
```