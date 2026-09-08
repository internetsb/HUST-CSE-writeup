# 高级工具与逆向专题-Binwalk工具使用-G3 WriteUp

对于提取squashfs文件系统的固件，需要安装squashfs-tools工具包：

```bash
apt install squashfs-tools
```

## 分析

提取出文件系统后，发现`/etc/config/flag.conf`文件中有加密的flag：

```
CONFIG_FLAG=synt{3q9o6s2p-8n1r-4q7o-ns9p-1r4n7q2o6p8s}
```

很明显的flag结构，使用随波逐流CTF工具一键解密，该flag使用凯撒加密。

还原出flag：

```
flag{3d9b6f2c-8a1e-4d7b-af9c-1e4a7d2b6c8f}
```
