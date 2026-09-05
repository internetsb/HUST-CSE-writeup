# 内网渗透与高级社工-终端EDR绕过-G1 WriteUp

打开目标页面，看到一个「主机运维执行面板」，页面提示本机部署了终端检测响应（EDR）代理，会对下发的运维命令做命令行特征审计，命中恶意特征的命令将被实时阻断。页面提供了一个文本框用于输入 shell 命令，以及一个「下发执行」按钮。

先执行一条基础命令探测环境。在输入框中输入 `id` 并点击下发执行，返回 `uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)`，说明命令可以正常执行，当前以低权限用户 `ctf` 运行。

![执行 id 命令，确认命令可执行](https://k13in-images.oss-cn-wuhan-lr.aliyuncs.com/02-id.png)

接下来定位目标文件。输入 `ls /` 查看根目录，输出中可以看到一个名为 `flag` 的文件，确认目标就是读取 `/flag`。

![ls / 列出根目录，发现 flag 文件](https://k13in-images.oss-cn-wuhan-lr.aliyuncs.com/03-ls.png)

直接尝试读取。输入 `cat /flag`，页面返回红色告警「EDR 告警：命令行命中恶意特征 «flag»，已阻断执行」，说明 EDR 对命令行做了子串匹配，`flag` 是敏感关键词。

![cat /flag 被 EDR 拦截，命中 flag 关键词](https://k13in-images.oss-cn-wuhan-lr.aliyuncs.com/04-cat-flag-blocked.png)

既然文件名触发了告警，尝试用通配符隐藏文件名。输入 `cat /f???`，`/f???` 会被 shell 展开为 `/flag`，命令行中不再包含 `flag` 子串。但这次返回的告警变成了「命中 «cat»」——`cat` 本身也在黑名单里。说明 EDR 同时检查了命令名和文件路径中的多个敏感子串。

![cat /f??? 被拦截，命中 cat 关键词](https://k13in-images.oss-cn-wuhan-lr.aliyuncs.com/05-cat-glob-blocked.png)

现在的思路很清晰：需要同时绕开命令名和文件名的子串检测。对于命令名，可以利用 shell 的反斜杠转义特性——`ca\t` 在字符串层面不包含子串 `cat`，但 shell 解析时会将反斜杠去掉，实际执行的仍然是 `cat`。对于文件名，继续使用通配符 `/f???`。两者组合后的 payload 为 `ca\t /f???`。

输入 `ca\t /f???` 并执行，EDR 的子串匹配找不到任何敏感关键词，命令顺利通过审计，shell 将其解析为 `cat /flag` 并执行，成功返回 flag。

![绕过 EDR 审计，成功读取 flag](https://k13in-images.oss-cn-wuhan-lr.aliyuncs.com/06-bypass-flag.png)

## 补充

使用`nl`命令可以查看带行号的文件内容，输入`nl /f*`，同样可以绕过 EDR 审计，成功读取 flag。