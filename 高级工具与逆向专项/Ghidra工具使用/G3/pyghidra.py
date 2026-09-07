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