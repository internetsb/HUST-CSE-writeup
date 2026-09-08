# 高级工具与逆向专题-Binwalk工具使用-G2 WriteUp

对`firmware.bin`文件进行递归提取

```bash
binwalk -Me firmware.bin
```

最终得到文件`payload_xor5A.bin`，该文件经过了异或加密，使用`cat`读取其内容为：

```
<6;=!8b<i;k>lwn9c?wn8h<wb>m;wo?h9l<c8i>k;'
```

使用Python脚本进行解密：

```python
data = b"<6;=!8b<i;k>lwn9c?wn8h<wb>m;wo?h9l<c8i>k;'"
plain = bytes(x ^ 0x5A for x in data)

print(plain)
```