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