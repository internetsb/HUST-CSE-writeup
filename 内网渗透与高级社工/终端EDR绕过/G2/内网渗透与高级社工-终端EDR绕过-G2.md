# 内网渗透与高级社工-终端EDR绕过-G2 WriteUp

## 分析

本关输入的命令会被嵌入`/bin/sh -c <COMMAND>`中执行，并且不允许派生新的进程。

```python
# /opt/app/app.py
import http.server
import json
import os
import subprocess

GUARD = "/opt/edr/exec_guard.so"

def run_cmd(cmd: str) -> dict:
    env = dict(os.environ, LD_PRELOAD=GUARD)
    try:
        p = subprocess.run(
            ["/bin/sh", "-c", cmd],
            capture_output=True,
            timeout=10,
            text=True,
            env=env,
        )
    except subprocess.TimeoutExpired:
        return {"blocked": False, "output": "执行超时"}

    if p.returncode == 42 or "__EDR_BLOCK__" in p.stderr:
        return {
            "blocked": True,
            "alert": "EDR 告警：服务进程派生子进程（execve），行为已阻断",
        }

    out = p.stdout
    if p.stderr and "__EDR_BLOCK__" not in p.stderr:
        out += p.stderr
    return {"blocked": False, "output": out[:8000]}
```

## 解题

可以使用shell的内置命令来绕过EDR的execve检测，因为这些内置命令不会派生新的进程。常见的内置命令包括`cd`, `echo`, `export`, `alias`, `set`, `unset`, `source`, `read`, `test`, `printf`等。

Payload：

```bash
read FLAG < /flag && echo $FLAG
```

将/flag读入环境变量FLAG中并输出，成功获取到flag。