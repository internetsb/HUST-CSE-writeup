# 高级工具与逆向专题-Binwalk工具使用-G1 WriteUp

Binwalk 是一款专门用于固件分析的命令行工具，它的核心能力是扫描任意二进制文件，通过内置的数百条魔数（magic bytes）签名规则识别出文件中嵌入的各种已知格式——压缩包、文件系统、可执行文件、证书、图片等等。在 CTF Misc 和逆向题目中，Binwalk 几乎是拿到附件后的第一道工序：很多题目会将 flag 或关键数据藏在一个看似正常的文件（图片、音频、固件）内部，表面上用常规软件打开毫无异常，但 Binwalk 能透视其内部结构，揭示隐藏的数据段。最常用的两个姿势是 `binwalk <file>` 纯扫描，列出文件中识别到的所有嵌入数据及其偏移地址；以及 `binwalk -e <file>` 扫描并自动提取，Binwalk 会根据识别到的格式调用对应的解压/提取逻辑，将嵌入数据释放到磁盘上供进一步分析。

拿到附件 `logo.png`，用 `file` 命令确认它确实是一张合法的 PNG 图片。但 CTF 中图片文件经常藏有额外数据，于是直接上 binwalk 对其进行固件级扫描，执行 `binwalk logo.png`。

![binwalk扫描结果](https://k13in-images.oss-cn-wuhan-lr.aliyuncs.com/binwalk_scan.png)

扫描结果显示这张 PNG 并不简单：偏移 0x0 处是正常的 PNG 图像数据，大小 2315 字节；紧随其后在偏移 0x90B 处藏了一段 gzip 压缩数据，大小 76 字节；偏移 0x957 处还附带了一个 32 位 x86 ELF 可执行文件。显然，出题人把额外的数据拼接在了 PNG 文件末尾，而 PNG 查看器只会读取到 IEND 标记就停止，所以打开图片看起来完全正常，隐藏数据不会被察觉。

接下来用 `binwalk -e logo.png` 对文件进行自动提取。

![binwalk提取结果](https://k13in-images.oss-cn-wuhan-lr.aliyuncs.com/binwalk_extract.png)

binwalk 成功解压了偏移 0x90B 处的 gzip 数据，提取结果保存在 `extractions/logo.png.extracted/90B/decompressed.bin` 中。需要注意的是，不同版本的 Binwalk 提取文件的输出目录并不相同：Binwalk v3.x 及以上版本默认将提取结果放在当前目录下的 `extractions/` 子目录中，而较早的 Binwalk v2.x 则直接在当前目录生成以 `_<文件名>.extracted` 命名的目录（例如 `_logo.png.extracted`）。如果执行提取后找不到输出目录，用 `ls` 看一下当前目录即可确认实际路径。接着用 `cat` 查看解压后的文件内容。

![查看解压文件](https://k13in-images.oss-cn-wuhan-lr.aliyuncs.com/cat_decode.png)

文件内容是一串 Base64 编码的字符串：`ZmxhZ3tlNGE3YzJmOS0xYjNkLTRlOGEtOWM2Zi0yZDViOGUxYTRmN2N9`。看到这种纯 ASCII 且以大写 Z 开头的字符串，第一反应就是 Base64。使用 [CyberChef](https://gchq.github.io/CyberChef) 进行解码：

![image-20260824160817660](https://k13in-images.oss-cn-wuhan-lr.aliyuncs.com/image-20260824160817660.png)