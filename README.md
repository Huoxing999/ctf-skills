# 🏴 CTF-Skills

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CTF](https://img.shields.io/badge/CTF-Skills-red.svg)](https://github.com)
[![Python](https://img.shields.io/badge/Python-3.6%2B-blue.svg)](https://www.python.org)
[![Shell](https://img.shields.io/badge/Shell-Bash-green.svg)](https://www.gnu.org/software/bash/)

> 🏴 一套完整的 CTF (Capture The Flag) 解题技能包，涵盖 **Web、Crypto、Reverse、Stego、SQLi、Misc** 六大方向。
> 每个模块包含完整的理论文档、决策树、代码模板和可直接运行的自动化脚本。

**A complete CTF skill toolkit covering Web, Crypto, Reverse Engineering, Steganography, SQL Injection, and Misc challenges.**

---

## 📚 目录 Table of Contents

- [📁 目录结构](#-目录结构)
- [🎯 各模块说明](#-各模块说明)
- [🚀 快速开始](#-快速开始)
- [📋 解题决策流程](#-解题决策流程)
- [🏆 已解题记录](#-已解题记录)
- [🛠️ 环境要求](#️-环境要求)
- [📄 License](#-license)

---

## 📁 目录结构

```
CTF-Skills/
├── README.md                    ← 总索引（你在这里）
├── ctf-web/                     # 🌐 Web 安全挑战
│   ├── SKILL.md                 # 完整技能文档
│   └── scripts/
│       └── web_fuzz.sh          # 一键 Web 模糊测试脚本
├── ctf-crypto/                  # 🔐 密码学挑战
│   ├── SKILL.md
│   └── scripts/
│       └── crypto_toolkit.py    # 自动编码检测与解码工具
├── ctf-reverse/                 # ⚙️ 逆向工程挑战
│   ├── SKILL.md
│   └── scripts/
│       ├── disasm_helper.py     # 反汇编辅助工具
│       ├── pe_analyze.py        # PE 文件分析工具
│       └── tea_solve.py         # TEA 加密解密模板
├── ctf-stego/                   # 🖼️ 隐写术挑战
│   ├── SKILL.md
│   ├── scripts/
│   ├── references/
│   └── assets/
├── ctf-sqli/                    # 💉 SQL 注入挑战
│   ├── SKILL.md
│   └── scripts/
│       └── sqli_toolkit.py      # 自动化 SQL 注入工具
└── ctf-misc/                    # 🎲 杂项挑战
    ├── SKILL.md
    └── scripts/
        └── esoteric_decoder.py  # 小众语言解码工具
```

---

## 🎯 各模块说明

| 模块 | 适用题型 | 核心技术 | 关键词 |
|------|---------|---------|--------|
| [**ctf-web**](./ctf-web/SKILL.md) 🌐 | HTTP 方法绕过、CORS、请求头伪造、命令注入、文件包含、SSRF、SSTI | curl、burpsuite | `PATCH`, `Origin`, `php://filter`, `{{7*7}}` |
| [**ctf-crypto**](./ctf-crypto/SKILL.md) 🔐 | Base64/Hex/ROT13 编码、XOR/AES/RSA 加密、古典密码 | Python、pycryptodome | `0x`, `base64`, `N=`, `e=`, `c=` |
| [**ctf-reverse**](./ctf-reverse/SKILL.md) ⚙️ | EXE/ELF 逆向、脱壳、反汇编、算法识别、密钥提取 | capstone、pefile、upx | `UPX`, `TEA`, `0x9e3779b9` |
| [**ctf-stego**](./ctf-stego/SKILL.md) 🖼️ | 图片隐写、文件附加、元数据隐藏、LSB 提取 | binwalk、steghide、PIL | `.png`, `.jpg`, `EXIF`, `LSB` |
| [**ctf-sqli**](./ctf-sqli/SKILL.md) 💉 | SQL 注入、登录绕过、UNION 提取、盲注、WAF 绕过 | sqlmap | `' OR 1=1`, `UNION SELECT` |
| [**ctf-misc**](./ctf-misc/SKILL.md) 🎲 | 流量分析、内存取证、小众语言、日志分析、OSINT | volatility、tshark、scapy | `.pcap`, `brainfuck`, `morse` |

---

## 🚀 快速开始

### 安装依赖

```bash
# Python 依赖
pip install requests pycryptodome capstone pefile Pillow scapy

# 系统工具
sudo apt install binwalk steghide exiftool upx sqlmap tshark
```

### Web 模糊测试（自动化探测）

```bash
chmod +x ctf-web/scripts/web_fuzz.sh
./ctf-web/scripts/web_fuzz.sh "http://target/challenge.php"
```

脚本自动测试：所有 HTTP 方法 / 常见请求头 / CORS Origin / Cookie / 参数注入 / 并输出高亮命中结果。

### 密码学自动解码

```bash
# 自动检测并解码（支持 base64/hex/rot13/binary/morse）
python3 ctf-crypto/scripts/crypto_toolkit.py "ZmxhZ3t0ZXN0fQ=="

# 输出：[BASE64] flag{test}
```

### SQL 注入自动化

```bash
# GET 注入
python3 ctf-sqli/scripts/sqli_toolkit.py "http://target/page.php?id=1"

# POST 注入
python3 ctf-sqli/scripts/sqli_toolkit.py "http://target/login.php" \
  --method POST --data "username=INJECT&password=x"

# SQLMap 快速命令
sqlmap -u "http://target/?id=1" --dbs --batch
sqlmap -u "http://target/?id=1" -D mydb -T flags --dump --batch
```

### 小众语言解码（Brainfuck / Morse / Binary）

```bash
# Brainfuck
python3 ctf-misc/scripts/esoteric_decoder.py "++++++++[>++++[>++>+++>+++>+<<<<-]>+>+>->>+[<]<-]"

# Morse code
python3 ctf-misc/scripts/esoteric_decoder.py ".... . .-.. .-.. ---"

# Binary
python3 ctf-misc/scripts/esoteric_decoder.py "01100110 01101100 01100001 01100111"
```

### TEA 解密（逆向）

```python
# ctf-reverse/scripts/tea_solve.py
from tea_solve import tea_decrypt
key = [0x12345678, 0x9ABCDEF0, 0xFEDCBA98, 0x76543210]
cipher = [0xABCD1234, 0xEF567890]
print(tea_decrypt(cipher, key))
```

---

## 📋 解题决策流程

```
拿到题目
  │
  ├─ 🌐 Web 页面？ ──────────────────────────────► ctf-web/SKILL.md
  │   ├─ 逐一测试 HTTP 方法 (GET/POST/PUT/PATCH/DELETE/OPTIONS/HEAD)
  │   ├─ 测试请求头 (Origin/Referer/Cookie/Authorization/X-Forwarded-For)
  │   ├─ 检查隐藏路径和参数 (?source=1 / ?debug=1 / ?highlight=1)
  │   └─ 测试注入 (SQLi / 命令注入 / SSTI / 文件包含)
  │
  ├─ 🔐 编码/密文？ ─────────────────────────────► ctf-crypto/SKILL.md
  │   ├─ 自动检测编码类型 (base64 / hex / rot13 / binary)
  │   ├─ 古典密码 (Caesar / Vigenere / 频率分析)
  │   └─ 现代密码 (XOR / AES / RSA — 找 N, e, c, key)
  │
  ├─ ⚙️  可执行文件？ ────────────────────────────► ctf-reverse/SKILL.md
  │   ├─ 检查壳 (UPX / MPRESS) → 脱壳
  │   ├─ strings 提取可见字符串
  │   ├─ 反汇编 → 识别算法 (TEA / XOR / RC4 / AES)
  │   └─ 提取密钥和密文 → Python 解密
  │
  ├─ 🖼️  图片/音频文件？ ─────────────────────────► ctf-stego/SKILL.md
  │   ├─ 直接查看（flag 可能可见）
  │   ├─ exiftool 检查元数据 (EXIF)
  │   ├─ strings / binwalk 提取嵌入数据
  │   └─ steghide / PIL LSB 隐写提取
  │
  ├─ 💉 登录表单 / 数据库相关？ ──────────────────► ctf-sqli/SKILL.md
  │   ├─ ' OR '1'='1'--  绕过登录
  │   ├─ UNION SELECT 枚举列数 → 提取数据
  │   └─ 盲注 (布尔/时间) → sqlmap 自动化
  │
  └─ 🎲 其他（流量/内存/奇怪格式）？ ─────────────► ctf-misc/SKILL.md
      ├─ .pcap → wireshark / tshark / scapy 分析
      ├─ 内存镜像 → volatility 取证
      ├─ 小众语言 → brainfuck / ook / whitespace 解码器
      └─ 日志 → grep / awk 过滤关键字
```

---

## 🏆 已解题记录

| 题目 | 类型 | Flag | 解法要点 |
|------|------|------|---------|
| ez_arithmetic | ⚙️ Reverse | `flag{203f12f62c9ed69e810f404bd7003ba7}` | UPX 脱壳 → TEA 解密 → XOR 异或 |
| 简单请求 (2.php) | 🌐 Web | `flag{you_win_the_lottery_!}` | `PATCH` 方法（非 CORS 简单请求）触发 |

---

## 🛠️ 环境要求

| 工具 | 用途 | 安装 |
|------|------|------|
| Python 3.6+ | 密码学/逆向/SQLi 脚本 | `apt install python3` |
| curl | Web 测试 | 预装 |
| sqlmap | SQL 注入自动化 | `apt install sqlmap` |
| binwalk | 隐写/固件分析 | `apt install binwalk` |
| steghide | 图片隐写提取 | `apt install steghide` |
| exiftool | EXIF 元数据查看 | `apt install libimage-exiftool-perl` |
| upx | 脱壳工具 | `apt install upx` |
| volatility | 内存取证 | `pip install volatility3` |
| tshark | 命令行流量分析 | `apt install tshark` |
| capstone | 反汇编框架 | `pip install capstone` |
| pefile | PE 文件解析 | `pip install pefile` |
| pycryptodome | 密码学库 | `pip install pycryptodome` |

---

## 📄 License

MIT License — 自由使用、修改和分发。

---

*🚩 Built for CTF competitions. Keep hacking, keep learning!*

*持续更新中 — 遇到新题型会补充对应的 Skill 和脚本。*
