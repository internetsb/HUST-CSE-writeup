# 高级工具与逆向专项-Ghidra工具使用-G3 WriteUp

## PyGhidra

若要通过Python脚本来使用Ghidra的API，需要安装PyGhidra。

通过运行`support/pyghidraRun`，会自动执行
- 创建虚拟环境
- 安装PyGhidra
- 打开Ghidra

打开Ghidra后，选择`Window->Script Manager`，点击按钮`Create New Script`，选择PyGhidra即可开始编写。

[文档参考](https://nationalsecurityagency-ghidra.mintlify.app/api/pyghidra)

## 分析

对`verify`函数反编译结果进行初步重命名：

```c
int verify(char *ctx,uchar *sig,size_t siglen,uchar *tbs,size_t tbslen)

{
  byte c;
  uint correct;
  int equal;
  size_t stringlen;
  long count;
  long in_FS_OFFSET;
  undefined1 start_of_flag;
  undefined1 local_67;
  undefined1 local_66;
  undefined1 local_65;
  undefined1 local_64;
  byte flag_content [36];
  undefined1 local_3f;
  undefined1 end_of_flag;
  long local_30;
  
  local_30 = *(long *)(in_FS_OFFSET + 0x28);
  stringlen = strlen(ctx);
  correct = 0;
  if ((stringlen == 0x2a) && (ctx[0x29] == '}')) {
                    /* flag{} */
    start_of_flag = 0x66;
    local_67 = 0x6c;
    local_66 = 0x61;
    local_65 = 0x67;
    local_64 = 0x7b;
                    /* flag内容 */
    count = 0;
    do {
      c = decrypt_char((uint)(ushort)(CONCAT11((&ASSEMBLE_HI)[count],(&ASSEMBLE_LO)[count]) >> 2),
                       (byte)(&ASSEMBLE_LO)[count] & 3);
      flag_content[count] = c;
      count = count + 1;
    } while (count != 0x24);
                    /* 比较 */
    local_3f = 0x7d;
    end_of_flag = 0;
    equal = memcmp(ctx,&start_of_flag,0x2b);
    correct = (uint)(equal == 0);
  }
  if (local_30 == *(long *)(in_FS_OFFSET + 0x28)) {
    return correct;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

*CONCAT11用于将两个1字节的值合并成一个2字节的值*

核心在于`decrypt_char`函数，其接收两个参数进行运算，较为简单：

```c
char decrypt_char(int param_1,int param_2)
{
  int s;
  
  s = param_1 * 7 + 3;
  return ((char)s + (char)(s / 0xfb) * '\x05' ^
         *(byte *)(*(long *)(strs.0 + (long)param_1 * 8) + (long)param_2)) & 0x7f;
}
```

在脚本管理器中编写PyGhidra脚本并运行，获得flag：

```python
from ghidra.program.model.address import Address

def get_addr(name):
    symbols = getSymbols(name, None)
    if symbols:
        return symbols[0].getAddress()
    return None

def decrypt_flag():
    # 获取全局变量地址
    hi_addr = get_addr("ASSEMBLE_HI")
    lo_addr = get_addr("ASSEMBLE_LO")
    strs_addr = get_addr("strs.0")

    if not hi_addr or not lo_addr or not strs_addr:
        print("[-] 未找到必要的符号地址，请检查 ASSEMBLE_HI, ASSEMBLE_LO 或 strs.0 的命名。")
        return

    mem = currentProgram.getMemory()
    space = currentProgram.getAddressFactory().getDefaultAddressSpace()
    
    flag_content = ""
    print("[+] 正在提取并解密 Flag...")
    
    for i in range(0x24): # 循环 36 次 (0x24)
        # 获取 HI 和 LO 字节
        hi = mem.getByte(hi_addr.add(i)) & 0xFF
        lo = mem.getByte(lo_addr.add(i)) & 0xFF
        
        concat_val = (hi << 8) | lo
        param_1 = concat_val >> 2
        param_2 = lo & 3
        s = param_1 * 7 + 3
        
        # 寻址指针数组获取具体的混淆字节
        ptr_offset = strs_addr.add(param_1 * 8)
        str_ptr = mem.getLong(ptr_offset)
        
        target_addr = space.getAddress(str_ptr + param_2)
        xor_byte = mem.getByte(target_addr) & 0xFF
        
        calc_val = (s + (s // 251) * 5) & 0xFF # & 0xFF 模拟char类型溢出
        decrypted = (calc_val ^ xor_byte) & 0x7F
        
        flag_content += chr(decrypted)
        
    print("[+] 解密完成！\nflag{%s}" % flag_content)

decrypt_flag()
```