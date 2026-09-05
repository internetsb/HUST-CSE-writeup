# 内网渗透与高级社工-免杀payload制作-G1 WriteUp

打开目标页面，映入眼帘的是一个名为「代码试验场」的在线工具，页面说明称可以在隔离环境中试运行 PHP 代码片段并即时查看输出结果。页面中央有一个代码输入框和一个「运行」按钮，placeholder 提示可以输入类似 `echo strtoupper('hello');` 的 PHP 代码。

先提交一段正常代码确认后端行为。在输入框填入 `echo strtoupper('hello');` 并点击运行，页面返回绿色提示「✓ 运行完成」，输出区域显示 `HELLO`。这说明后端确实在执行用户提交的 PHP 代码并回显结果——存在 eval 型代码执行，目标是想办法读取服务器上的 flag 文件。

![提交正常代码，返回 HELLO](https://k13in-images.oss-cn-wuhan-lr.aliyuncs.com/02-normal-exec.png)

既然能执行代码，最直接的思路是调用系统命令。提交 `system('id');` 试图执行 shell 命令，页面返回红色提示「✕ 运行请求未通过安全校验」，说明存在某种过滤机制拦截了请求。

![system 函数被拦截](https://k13in-images.oss-cn-wuhan-lr.aliyuncs.com/03-blocked-system.png)

继续 fuzz 探测过滤边界。依次尝试 `exec`、`shell_exec`、`passthru`、`popen` 等命令执行函数，全部被拦。换一个思路，尝试用 PHP 文件读取函数代替命令执行：提交 `readfile('/flag');`，同样被拦。进一步二分定位触发点：`readfile('x')` 能通过，`readfile('/')` 被拦——说明 `/` 字符本身就在黑名单里；单独提交 `echo 'flag';` 也被拦——`flag` 这个词也是敏感关键词。经过反复测试，可以归纳出黑名单包含：命令执行类函数名（`system`、`exec`、`shell_exec`、`passthru`、`popen`、`proc_open`）、`cat`、`flag`、`/`、`|`、反引号、`$`、`>`、`<`。匹配方式是子串检测，命中任意一个即拦截。

![readfile('/flag') 同样被拦截](https://k13in-images.oss-cn-wuhan-lr.aliyuncs.com/04-blocked-readfile.png)

黑名单只针对了命令执行类函数，而 PHP 原生的文件读取函数 `readfile`、`file_get_contents`、`highlight_file` 等并不在其中，可以正常使用。问题在于如何构造路径 `/flag` 而不触发 `/` 和 `flag` 两个敏感词。PHP 的 `chr()` 函数可以通过 ASCII 码生成字符，`chr(47)` 就是 `/`；字符串拼接运算符 `.` 可以将 `'fl'.'ag'` 拼成 `flag`，源码中不会出现连续的 `flag` 四个字母。组合起来，最终 payload 为：

```
readfile(chr(47).'fl'.'ag');
```

提交这段代码，页面返回「✓ 运行完成」，输出区域成功显示了 flag 内容。

![提交绕过 payload 后成功获取 flag](https://k13in-images.oss-cn-wuhan-lr.aliyuncs.com/05-flag.png)
