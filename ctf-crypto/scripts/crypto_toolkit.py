#!/usr/bin/env python3
"""
CTF Crypto Toolkit - 一键密码学解题工具
Usage: python3 crypto_toolkit.py <encoded_data>
"""
import sys, base64, hashlib, string
from itertools import product

def try_base64(data):
    try:
        padded = data + '=' * (-len(data) % 4)
        decoded = base64.b64decode(padded)
        if decoded and all(32 <= b < 127 or b in (10,13) for b in decoded):
            return decoded.decode('utf-8', errors='ignore')
    except: pass
    return None

def try_hex(data):
    try:
        if len(data) % 2 == 0 and all(c in '0123456789abcdefABCDEF' for c in data):
            decoded = bytes.fromhex(data).decode('utf-8', errors='ignore')
            return decoded
    except: pass
    return None

def try_rot13(data):
    result = data.translate(str.maketrans(
        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
        'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'))
    return result if result != data else None

def try_caesar_all(data):
    results = []
    clean = ''.join(c for c in data if c.isalpha())
    if not clean:
        return results
    for shift in range(1, 26):
        decrypted = data.translate(str.maketrans(
            string.ascii_uppercase + string.ascii_lowercase,
            string.ascii_uppercase[shift:] + string.ascii_uppercase[:shift] +
            string.ascii_lowercase[shift:] + string.ascii_lowercase[:shift]))
        if 'flag' in decrypted.lower():
            results.append((shift, decrypted))
    return results

def try_xor_single(data_bytes):
    results = []
    for key in range(256):
        decrypted = bytes(b ^ key for b in data_bytes)
        printable = sum(1 for b in decrypted if 32 <= b < 127)
        if printable / len(decrypted) > 0.85:
            try:
                text = decrypted.decode('utf-8', errors='ignore')
                results.append((key, text))
            except: pass
    return results

def try_base32(data):
    try:
        padded = data + '=' * (-len(data) % 8)
        decoded = base64.b32decode(padded)
        return decoded.decode('utf-8', errors='ignore')
    except: pass
    return None

def identify_hash(h):
    h = h.strip()
    mapping = {32: 'MD5', 40: 'SHA-1', 56: 'SHA-224', 64: 'SHA-256', 96: 'SHA-384', 128: 'SHA-512'}
    return mapping.get(len(h), 'Unknown')

def crack_md5(target):
    target = target.lower()
    for word in ['admin','password','123456','flag','ctf','root','test','guest','admin123','key','secret']:
        if hashlib.md5(word.encode()).hexdigest() == target:
            return word
    for i in range(1000000):
        if hashlib.md5(str(i).encode()).hexdigest() == target:
            return str(i)
    return None

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 crypto_toolkit.py <data>")
        print("Example: python3 crypto_toolkit.py 'ZmxhZ3t0ZXN0fQ=='")
        sys.exit(1)
    
    data = sys.argv[1].strip()
    print(f"Input ({len(data)} chars): {data[:100]}{'...' if len(data) > 100 else ''}")
    print("=" * 60)
    
    # Hash identification
    if all(c in '0123456789abcdefABCDEF' for c in data) and len(data) in [32,40,56,64,96,128]:
        hash_type = identify_hash(data)
        print(f"\n[HASH] Detected: {hash_type}")
        if hash_type == 'MD5':
            result = crack_md5(data)
            if result: print(f"[CRACKED] {data} = {result}")
    
    # Base64
    result = try_base64(data)
    if result:
        print(f"\n[BASE64] {result[:200]}")
    
    # Base32
    result = try_base32(data)
    if result:
        print(f"\n[BASE32] {result[:200]}")
    
    # Hex
    result = try_hex(data)
    if result:
        print(f"\n[HEX] {result[:200]}")
    
    # ROT13
    result = try_rot13(data)
    if result and 'flag' in result.lower():
        print(f"\n[ROT13] {result}")
    
    # Caesar brute force
    caesar_hits = try_caesar_all(data)
    for shift, text in caesar_hits:
        print(f"\n[CAESAR shift={shift}] {text[:200]}")
    
    # XOR (if data is base64-encoded bytes)
    try:
        raw = base64.b64decode(data + '=' * (-len(data) % 4))
        if len(raw) < 1000:
            xor_results = try_xor_single(raw)
            for key, text in xor_results[:5]:
                print(f"\n[XOR key={key:#04x}] {text[:100]}")
    except: pass

if __name__ == '__main__':
    main()
