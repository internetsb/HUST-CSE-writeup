# 高级工具与逆向专项-Ghidra工具使用-G4 WriteUp

## 分析

对`verify`函数进行初步Rename与Retype后如下：

```c
bool verify(char *string)

{
  int isequal;
  size_t str_len;
  longlong len_count;
  char *buff_p;
  char *p;
  char *content_p;
  bool correct;
  char local_78;
  char local_77;
  char local_76;
  char local_75;
  char local_74;
  char flag_content [36];
  char local_4f;
  char local_4e;
  char buff [48];
  
  str_len = strlen(string);
  correct = false;
  if ((str_len == 0x2a) && (string[0x29] == '}')) {
    p = buff;
                    /* 清空 */
    for (len_count = 0x25; len_count != 0; len_count = len_count + -1) {
      *p = '\0';
      p = p + 1;
    }
                    /* 生成flag内容 */
    vm_run(0x140004060,(longlong)buff);
    local_78 = 'f';
    local_77 = 'l';
    local_76 = 'a';
    local_75 = 'g';
    local_74 = '{';
    buff_p = buff;
    content_p = flag_content;
    for (len_count = 9; len_count != 0; len_count = len_count + -1) {
      *(undefined4 *)content_p = *(undefined4 *)buff_p;
      buff_p = buff_p + 4;
      content_p = content_p + 4;
    }
    local_4f = '}';
    local_4e = '\0';
    isequal = memcmp(string,&local_78,0x2b);
    correct = isequal == 0;
  }
  return correct;
}
```

`vmrun`本质是一个小型的CPU，取出指令码并解释执行，最终生成flag内容。

```c
void vm_run(longlong addr,longlong buff)
{
  byte *pbVar1;
  int pc;
  int iVar2;
  int sp;
  byte Stack [72];
  
  pc = 0;
  sp = 0;
  while( true ) {
    iVar2 = pc + 1;
    if (5 < *(byte *)(addr + pc)) break;
                    /* WARNING: Could not find normalized switch variable to match jumptable */
    switch(*(undefined1 *)(addr + pc)) {
    case 0:
      goto quit;
    case 1:
      pc = pc + 2;
      Stack[sp] = *(byte *)(addr + iVar2);
      sp = sp + 1;
      break;
    case 2:
      Stack[sp + -2] = Stack[sp + -2] ^ Stack[sp + -1];
      pc = iVar2;
      sp = sp + -1;
      break;
    case 3:
      pbVar1 = Stack + (sp + -1);
      *pbVar1 = *pbVar1 << 1 | (char)*pbVar1 < '\0';
      pc = iVar2;
      break;
    case 4:
      Stack[sp + -1] = Stack[sp + -1] + *(char *)(addr + iVar2);
      pc = pc + 2;
      break;
    case 5:
      *(byte *)(buff + (ulonglong)*(byte *)(addr + iVar2)) = Stack[sp + -1];
      pc = pc + 2;
      sp = sp + -1;
    }
  }
quit:
  return;
}
```

## 求解Ghidra脚本

```python
# Name: VMExtractor.py
# Description: Emulate VM instructions at 0x140004060 to extract the output buffer.
# @category: Custom

from ghidra.program.model.address import Address

def get_unsigned_byte(address):
    # Ghidra getByte returns signed bytes (-128 to 127)
    b = getByte(address)
    return b if b >= 0 else b + 256

def run_vm(base_offset):
    space = currentProgram.getAddressFactory().getDefaultAddressSpace()
    addr = space.getAddress(base_offset)
    
    stack = [0] * 72
    sp = 0
    pc = 0
    buff = {}  # 字典模拟 buffer (index -> byte)
    
    print("[*] Starting VM execution at {}".format(addr))
    
    while True:
        curr_addr = addr.add(pc)
        opcode = get_unsigned_byte(curr_addr)
        
        if opcode > 5:
            print("[-] Terminated: Unknown opcode {} at PC: {}".format(opcode, pc))
            break
            
        if opcode == 0:    # quit
            break
            
        elif opcode == 1:  # push immediate
            operand = get_unsigned_byte(addr.add(pc + 1))
            stack[sp] = operand
            sp += 1
            pc += 2
            
        elif opcode == 2:  # xor 
            stack[sp - 2] = (stack[sp - 2] ^ stack[sp - 1]) & 0xFF
            sp -= 1
            pc += 1
            
        elif opcode == 3:  # rol 1 (8-bit)
            val = stack[sp - 1]
            msb = (val & 0x80) >> 7
            stack[sp - 1] = ((val << 1) & 0xFF) | msb
            pc += 1
            
        elif opcode == 4:  # add immediate
            operand = get_unsigned_byte(addr.add(pc + 1))
            stack[sp - 1] = (stack[sp - 1] + operand) & 0xFF
            pc += 2
            
        elif opcode == 5:  # pop to buff[immediate]
            operand = get_unsigned_byte(addr.add(pc + 1))
            buff[operand] = stack[sp - 1]
            sp -= 1
            pc += 2
            
    # 解析并打印结果
    print("[*] VM execution completed. Extracted buffer:")
    if not buff:
        print("Buffer is empty.")
        return
        
    max_idx = max(buff.keys())
    result_str = ""
    result_hex = []
    
    for i in range(max_idx + 1):
        val = buff.get(i, 0)
        result_hex.append("{:02x}".format(val))
        # 仅拼接可打印 ASCII 字符
        if 32 <= val <= 126:
            result_str += chr(val)
        else:
            result_str += "."
            
    print(f"flag{{{result_str}}}")

# 传入目标 VM 字节码的基址
run_vm(0x140004060)
```
