#!/usr/bin/env bash
# CTF Web Challenge Fuzzer - 一键自动化探测
# Usage: ./web_fuzz.sh <url>

URL="${1:?Usage: $0 <url>}"
OUT="web_fuzz_result.txt"
> "$OUT"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

hit_count=0

check() {
  local tag="$1"; shift
  body=$(curl -si --connect-timeout 5 --max-time 10 "$@" 2>&1)
  echo "=== $tag ===" >> "$OUT"
  echo "$body" >> "$OUT"
  echo "" >> "$OUT"
  if echo "$body" | grep -qiE "flag\{|ctf\{|thtf\{|congrat|success|well.done|HIT"; then
    echo -e "${GREEN}[HIT!] $tag${NC}"
    echo "🎉 HIT: $tag" >> "$OUT"
    hit_count=$((hit_count + 1))
    return 0
  fi
  return 1
}

echo "========================================="
echo " CTF Web Fuzzer"
echo " Target: $URL"
echo " Output: $OUT"
echo "========================================="

# HTTP Methods
echo -e "\n${YELLOW}[1/8] Testing HTTP Methods...${NC}"
for m in GET POST HEAD OPTIONS PUT DELETE PATCH TRACE; do
  check "METHOD $m" -X "$m" "$URL"
done

# Request Headers
echo -e "\n${YELLOW}[2/8] Testing Request Headers...${NC}"
check "Origin: self"       -H "Origin: $(echo $URL | sed 's|/[^/]*$||')" "$URL"
check "Origin: null"       -H "Origin: null" "$URL"
check "Origin: evil"       -H "Origin: http://evil.com" "$URL"
check "Referer: self"      -H "Referer: $URL" "$URL"
check "X-Forwarded-For"    -H "X-Forwarded-For: 127.0.0.1" "$URL"
check "X-Real-IP"          -H "X-Real-IP: 127.0.0.1" "$URL"
check "Client-IP"          -H "Client-IP: 127.0.0.1" "$URL"
check "Authorization"      -H "Authorization: Bearer test" "$URL"
check "X-Requested-With"   -H "X-Requested-With: XMLHttpRequest" "$URL"

# User-Agent
echo -e "\n${YELLOW}[3/8] Testing User-Agent...${NC}"
check "UA: Mozilla"     -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" "$URL"
check "UA: Googlebot"   -A "Googlebot/2.1 (+http://www.google.com/bot.html)" "$URL"
check "UA: curl"        -A "curl/7.68.0" "$URL"

# Content-Type
echo -e "\n${YELLOW}[4/8] Testing Content-Type...${NC}"
check "POST: form-data"    -X POST "$URL" -H "Content-Type: application/x-www-form-urlencoded" -d "key=value"
check "POST: JSON"         -X POST "$URL" -H "Content-Type: application/json" -d '{"key":"value"}'
check "POST: XML"          -X POST "$URL" -H "Content-Type: application/xml" -d '<root/>'
check "POST: text/plain"   -X POST "$URL" -H "Content-Type: text/plain" -d 'flag'

# Cookies
echo -e "\n${YELLOW}[5/8] Testing Cookies...${NC}"
for c in "admin=1" "isadmin=1" "flag=1" "role=admin" "user=admin" "logged_in=true" "token=admin"; do
  check "Cookie: $c" -H "Cookie: $c" "$URL"
done

# URL Parameters
echo -e "\n${YELLOW}[6/8] Testing URL Parameters...${NC}"
for p in flag admin debug source show_source view-source key id cmd file page lang action type pass; do
  check "PARAM $p=1" "$URL?$p=1"
  check "PARAM $p" "$URL?$p"
done

# POST Data
echo -e "\n${YELLOW}[7/8] Testing POST Data...${NC}"
for d in "flag=1" "admin=1" "key=flag" "debug=1" "source=1" "id=1" "cmd=id"; do
  check "POST: $d" -X POST -d "$d" "$URL"
done

# Hidden Paths
echo -e "\n${YELLOW}[8/8] Testing Hidden Paths...${NC}"
BASE=$(echo "$URL" | sed 's|/[^/]*$||')
for path in robots.txt .git/HEAD .env .htaccess phpinfo.php flag flag.txt \
  admin login test backup.sql index.php.bak config.php.bak \
  .well-known/ .DS_STORE WEB-INF/web.xml swagger json; do
  resp=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 3 "${BASE}/${path}" 2>&1)
  if [ "$resp" != "404" ] && [ "$resp" != "000" ]; then
    echo -e "${YELLOW}[${resp}] /${path}${NC}"
    echo "[${resp}] /${path}" >> "$OUT"
  fi
done

# Summary
echo ""
echo "========================================="
echo -e "Scan complete! Hits: ${GREEN}${hit_count}${NC}"
echo -e "Full results saved to: ${OUT}"
echo "========================================="
