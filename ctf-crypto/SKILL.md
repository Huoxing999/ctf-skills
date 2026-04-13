---
name: ctf-crypto
description: This skill should be used when solving CTF (Capture The Flag) cryptography challenges. Triggers include: decoding encoded text (base64, hex, ROT13, Caesar), breaking ciphers (XOR, AES, RSA, Vigenere), identifying encoding schemes, frequency analysis, and solving classical or modern crypto puzzles.
---

# CTF Cryptography

## Overview

This skill provides systematic workflows for solving CTF cryptography challenges, from simple encoding to complex cipher breaking. Focus on identifying the encoding/cipher type first, then applying the appropriate decryption method.

**Core principle**: Identify before decrypting -- most crypto challenges have obvious hints in the data format, length, or character set.

---

## Quick Start Checklist

1. Check data format (hex, base64, binary, mixed charset)
2. Try common encodings (base64, hex, ROT13, URL encode)
3. Identify cipher type by structure (block size, character set, patterns)
4. Apply frequency analysis for substitution ciphers
5. Look for known constants or weak keys
6. For RSA: factorize N, check for small primes, Fermat factorization

---

## Category 1: Encoding Detection & Decoding

### Auto-Detect Encoding Type

```python
import re, base64

def detect_and_decode(data: str) -> str:
    data = data.strip()
    
    # Hex: [0-9a-fA-F]{8,}
    if re.fullmatch(r'[0-9a-fA-F]+', data) and len(data) % 2 == 0 and len(data) >= 8:
        decoded = bytes.fromhex(data)
        print(f"[HEX] {decoded}")
        return decoded.decode('utf-8', errors='replace')
    
    # Base64: [A-Za-z0-9+/=]{4,} with proper padding
    if re.fullmatch(r'[A-Za-z0-9+/]+={0,2}', data) and len(data) % 4 == 0:
        try:
            decoded = base64.b64decode(data)
            if all(32 <= b < 127 or b in (10, 13, 9) for b in decoded):
                print(f"[BASE64] {decoded.decode('utf-8')}")
                return decoded.decode('utf-8')
        except: pass
    
    # Base32: [A-Z2-7=]{8,}
    if re.fullmatch(r'[A-Z2-7]+={0,6}', data) and len(data) % 8 == 0:
        try:
            decoded = base64.b32decode(data)
            print(f"[BASE32] {decoded}")
            return decoded.decode('utf-8', errors='replace')
        except: pass
    
    # ROT13
    rot13 = data.translate(str.maketrans(
        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
        'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'))
    if 'flag' in rot13.lower() or rot13 != data:
        print(f"[ROT13] {rot13}")
    
    # URL decode
    if '%' in data:
        try:
            decoded = data.encode().decode('unicode_escape')
            print(f"[URL_DECODE] {decoded}")
        except: pass
    
    print("[UNKNOWN] Could not auto-detect encoding")
    return data
```

### Multi-layer Encoding

```python
import base64

def multi_decode(data: str, max_layers=10):
    """自动检测并解密多层编码"""
    current = data.strip()
    for i in range(max_layers):
        prev = current
        # Try base64
        try:
            if len(current) % 4 == 0:
                decoded = base64.b64decode(current + '==' if current[-1] != '=' else current)
                if all(32 <= b < 127 or b in (10, 13) for b in decoded):
                    current = decoded.decode('utf-8', errors='ignore')
                    print(f"Layer {i+1}: Base64 -> {current[:100]}")
                    continue
        except: pass
        # Try hex
        try:
            if all(c in '0123456789abcdefABCDEF' for c in current) and len(current) % 2 == 0:
                decoded = bytes.fromhex(current).decode('utf-8', errors='ignore')
                if decoded.isprintable() or 'flag' in decoded.lower():
                    current = decoded
                    print(f"Layer {i+1}: Hex -> {current[:100]}")
                    continue
        except: pass
        break
    return current
```

---

## Category 2: Classical Ciphers

### Caesar Cipher (ROT-n)

```python
def caesar_decrypt(ciphertext: str, shift: int = None) -> list:
    """Caesar cipher brute force (all 26 shifts)"""
    results = []
    for s in range(26) if shift is None else [shift]:
        decrypted = ''
        for c in ciphertext:
            if c.isalpha():
                base = ord('A') if c.isupper() else ord('a')
                decrypted += chr((ord(c) - base - s) % 26 + base)
            else:
                decrypted += c
        results.append((s, decrypted))
        print(f"Shift {s:2d}: {decrypted}")
    return results
```

### Vigenere Cipher

```python
def vigenere_decrypt(ciphertext: str, key: str) -> str:
    decrypted = ''
    key_idx = 0
    for c in ciphertext:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            k = ord(key[key_idx % len(key)].lower()) - ord('a')
            decrypted += chr((ord(c) - base - k) % 26 + base)
            key_idx += 1
        else:
            decrypted += c
    return decrypted

# Vigenere key length detection (Kasiski / Index of Coincidence)
def vigenere_key_length(ct: str, max_key=20):
    from collections import Counter
    ct_clean = ''.join(c.upper() for c in ct if c.isalpha())
    scores = []
    for kl in range(1, max_key + 1):
        groups = ['' for _ in range(kl)]
        for i, c in enumerate(ct_clean):
            groups[i % kl] += c
        avg_ic = 0
        for g in groups:
            n = len(g)
            if n < 2: continue
            freq = Counter(g)
            ic = sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))
            avg_ic += ic
        avg_ic /= kl
        scores.append((kl, avg_ic))
    # English IC ≈ 0.0667, random ≈ 0.0385
    for kl, ic in sorted(scores, key=lambda x: -x[1])[:5]:
        marker = " <--" if ic > 0.06 else ""
        print(f"Key length {kl:2d}: IC = {ic:.4f}{marker}")
```

### Substitution Cipher (Frequency Analysis)

```python
def frequency_analysis(ciphertext: str):
    """English letter frequency analysis"""
    ct = ''.join(c.upper() for c in ciphertext if c.isalpha())
    from collections import Counter
    freq = Counter(ct)
    total = len(ct)
    
    # English letter frequency order
    english_freq = 'ETAOINSHRDLCUMWFGYPBVKJXQZ'
    
    print("Ciphertext frequency:")
    for letter, count in freq.most_common():
        bar = '#' * (count * 50 // total)
        print(f"  {letter}: {count:4d} ({count*100//total:2d}%) {bar}")
    
    # Suggest mapping
    print("\nSuggested mapping (by frequency):")
    ct_sorted = [c for c, _ in freq.most_common()]
    for i, ct_letter in enumerate(ct_sorted):
        if i < len(english_freq):
            print(f"  {ct_letter} -> {english_freq[i]}")
```

---

## Category 3: Modern Ciphers

### XOR

```python
def xor_decrypt(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

# Single-byte XOR brute force
def xor_single_byte_brute(ciphertext: bytes) -> list:
    results = []
    for key in range(256):
        decrypted = bytes(b ^ key for b in ciphertext)
        # Score based on printable ASCII ratio
        printable = sum(1 for b in decrypted if 32 <= b < 127 or b in (10, 13))
        score = printable / len(decrypted)
        if score > 0.9:
            results.append((key, score, decrypted))
    return sorted(results, key=lambda x: -x[1])

# Repeating key XOR
def xor_repeating_key(ciphertext: bytes, key_length: int = None) -> bytes:
    if key_length is None:
        # Try common key lengths
        for kl in range(1, 33):
            # Try single byte key for each position
            key = []
            for i in range(kl):
                block = ciphertext[i::kl]
                best = max(range(256), key=lambda k: sum(1 for b in block if (b^k) in range(32, 127)))
                key.append(best)
            result = xor_decrypt(ciphertext, bytes(key))
            if result[:4] == b'flag' or b'flag{' in result:
                return result
    return None

# XOR with known plaintext
def xor_known_plaintext(ciphertext: bytes, known_plaintext: bytes) -> bytes:
    return bytes(c ^ p for c, p in zip(ciphertext, known_plaintext))
```

### AES (ECB/CBC)

```python
from Crypto.Cipher import AES

# AES ECB Decrypt
def aes_ecb_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(ciphertext)

# AES CBC Decrypt
def aes_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.decrypt(ciphertext)

# AES ECB detection (repeated blocks = ECB mode)
def detect_ecb(ciphertext: bytes, block_size=16) -> bool:
    blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]
    return len(blocks) != len(set(blocks))

# Common CTF AES patterns:
# - Key is often "flag" padded, "1234567890abcdef", or derived from challenge
# - IV is often all zeros, first 16 bytes, or given in challenge
# - ECB oracle: can encrypt chosen plaintext to reveal key
```

### RSA

```python
import math

def rsa_common_factors(p, q=None, n=None, e=None, c=None):
    """Common RSA attack toolkit"""
    if p and q and n is None:
        n = p * q
    phi = (p - 1) * (q - 1)
    
    # Calculate private key
    if e:
        d = pow(e, -1, phi)
        print(f"n = {n}")
        print(f"e = {e}")
        print(f"d = {d}")
        print(f"phi = {phi}")
        
        # Decrypt
        if c:
            m = pow(c, d, n)
            flag = m.to_bytes((m.bit_length() + 7) // 8, 'big')
            print(f"Flag: {flag}")
            return flag

# Fermat factorization (works when p and q are close)
def fermat_factor(n):
    a = math.isqrt(n)
    if a * a < n:
        a += 1
    b2 = a * a - n
    for _ in range(1000000):
        b = math.isqrt(b2)
        if b * b == b2:
            p, q = a + b, a - b
            print(f"p = {p}, q = {q}")
            return p, q
        a += 1
        b2 = a * a - n
    print("Fermat factorization failed")
    return None, None

# Small prime factorization
def small_factor(n, limit=1000000):
    for i in range(2, limit):
        if n % i == 0:
            print(f"Found factor: {i}")
            return i, n // i
    print(f"No small factor found (up to {limit})")
    return None, None

# Wiener's attack (small private exponent d)
def wiener_attack(e, n):
    # Continued fraction expansion of e/n
    def continued_fraction(num, den):
        cf = []
        while den:
            q, r = divmod(num, den)
            cf.append(q)
            num, den = den, r
        return cf
    
    def convergents(cf):
        convs = []
        h_prev, h_curr = 0, 1
        k_prev, k_curr = 1, 0
        for a in cf:
            h_prev, h_curr = h_curr, a * h_curr + h_prev
            k_prev, k_curr = k_curr, a * k_curr + k_prev
            convs.append((h_curr, k_curr))
        return convs
    
    cf = continued_fraction(e, n)
    for k, d in convergents(cf):
        if k == 0: continue
        phi_n = (e * d - 1) // k
        # p + q = n - phi_n + 1, p * q = n
        s = n - phi_n + 1
        # Check if p and q are integers
        discriminant = s * s - 4 * n
        if discriminant >= 0:
            t = math.isqrt(discriminant)
            if t * t == discriminant:
                p = (s + t) // 2
                q = (s - t) // 2
                if p * q == n:
                    print(f"d = {d}, p = {p}, q = {q}")
                    return d, p, q
    print("Wiener attack failed")
    return None, None, None

# Common modulus attack (same n, different e)
def common_modulus_attack(c1, c2, e1, e2, n):
    from math import gcd
    g, s1, s2 = extended_gcd(e1, e2)
    if g != 1:
        print("e1 and e2 are not coprime, attack may fail")
        return None
    # c1^s1 * c2^s2 mod n = m^(e1*s1 + e2*s2) mod n = m^1 mod n
    if s1 < 0:
        c1 = pow(c1, -1, n)
        s1 = -s1
    if s2 < 0:
        c2 = pow(c2, -1, n)
        s2 = -s2
    m = (pow(c1, s1, n) * pow(c2, s2, n)) % n
    flag = m.to_bytes((m.bit_length() + 7) // 8, 'big')
    print(f"Flag: {flag}")
    return flag

def extended_gcd(a, b):
    if a == 0: return b, 0, 1
    g, x, y = extended_gcd(b % a, a)
    return g, y - (b // a) * x, x
```

---

## Category 4: Hash & Encoding Tools

### Hash Identification

```python
def identify_hash(hash_str: str):
    h = hash_str.strip()
    length = len(h)
    
    hashes = {
        8:   "CRC32",
        16:  "MySQL4 / NTLM (half) / FCS16",
        32:  "MD5",
        40:  "SHA-1 / RIPEMD-160",
        56:  "SHA-224 / SHA3-224",
        64:  "SHA-256 / SHA3-256 / BLAKE2s",
        96:  "SHA-384 / SHA3-384",
        128: "SHA-512 / SHA3-512 / BLAKE2b",
    }
    
    identified = hashes.get(length, f"Unknown (length={length})")
    
    # Check character set
    if all(c in '0123456789abcdef' for c in h):
        charset = "hex-lower"
    elif all(c in '0123456789ABCDEF' for c in h):
        charset = "hex-upper"
    elif all(c in '0123456789abcdefABCDEF' for c in h):
        charset = "hex-mixed"
    else:
        charset = "non-hex"
    
    print(f"Hash: {h[:50]}{'...' if len(h) > 50 else ''}")
    print(f"Length: {length} chars")
    print(f"Charset: {charset}")
    print(f"Likely type: {identified}")
```

### Common Hash Cracking

```python
import hashlib

def md5_crack(hash_val: str, wordlist: list = None):
    """MD5 brute force with common words"""
    hash_val = hash_val.lower()
    
    # Common CTF passwords
    common = ['admin', 'password', '123456', 'flag', 'ctf', 'root', 'test',
              'guest', 'admin123', 'password123', 'flag123', 'key', 'secret']
    if wordlist:
        common.extend(wordlist)
    
    for word in common:
        if hashlib.md5(word.encode()).hexdigest() == hash_val:
            print(f"[FOUND] {hash_val} = {word}")
            return word
    
    # Numeric brute force (1-999999)
    for i in range(1000000):
        if hashlib.md5(str(i).encode()).hexdigest() == hash_val:
            print(f"[FOUND] {hash_val} = {i}")
            return str(i)
    
    print("Not found")
    return None
```

---

## Category 5: Obfuscation & Custom Encoding

### Custom alphabet Base64

```python
import base64, string

def custom_base64_decode(data: str, custom_alphabet: str) -> str:
    """Decode base64 with custom alphabet"""
    std_alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    trans = str.maketrans(custom_alphabet, std_alphabet)
    std_data = data.translate(trans)
    # Fix padding
    std_data += '=' * (4 - len(std_data) % 4) % 4
    return base64.b64decode(std_data).decode('utf-8', errors='replace')

# Example: 如果 alphabet 被打乱了
# custom_base64_decode(encoded_text, "ZYXWVUTSRQPONMLKJIHGFEDCBAabcdefghijklmnopqrstuvwxyz0123456789+/")
```

### Reverse + Encode combinations

```python
def common_decode_chain(data: str) -> str:
    """Try common multi-encoding chains"""
    import base64
    
    chains = [
        lambda d: d[::-1],                                          # reverse
        lambda d: base64.b64decode(d).decode('utf-8', errors='ignore'),  # base64
        lambda d: bytes.fromhex(d).decode('utf-8', errors='ignore'),    # hex
        lambda d: d.translate(str.maketrans(                        # rot13
            'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
            'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm')),
    ]
    
    # Try all 2-chain and 3-chain combinations
    from itertools import product
    for r in [2, 3]:
        for combo in product(chains, repeat=r):
            try:
                result = data
                for func in combo:
                    result = func(result)
                if 'flag' in result.lower() or result.isprintable():
                    print(f"Chain: {[f.__name__ for f in combo]} -> {result[:100]}")
            except: pass
    return data
```

---

## Decision Tree

```
Start: Got encoded/encrypted data
  |
  +-- Is it readable text but makes no sense?
  |     Yes -> Substitution cipher (Caesar, Vigenere, etc.)
  |            Try ROT13 first
  |            Frequency analysis for monoalphabetic
  |            Kasiski method for polyalphabetic
  |
  +-- Is it only hex chars [0-9a-f]?
  |     Yes -> Hex decode, then re-analyze result
  |
  +-- Is it [A-Za-z0-9+/=] with length % 4 == 0?
  |     Yes -> Base64 decode, then re-analyze result
  |
  +-- Is it a long hex string (32/40/64 chars)?
  |     Yes -> Hash value (MD5/SHA1/SHA256)
  |            Crack with common passwords or online lookup
  |
  +-- Is it all numbers?
  |     Yes -> Try ASCII conversion, or modulo-26 for letters
  |
  +-- Given RSA parameters (n, e, c)?
  |     Yes -> Factorize n, compute d, decrypt c
  |            Try small factors, Fermat, Wiener
  |
  +-- Binary data with patterns?
        Yes -> XOR with common keys
               Single-byte brute force
               Known-plaintext attack
```

---

## Real Cases

### Case: Multi-layer Encoding

Common CTF pattern: base64 -> hex -> base64 -> rot13 -> flag
Solution: Apply multi_decode() iteratively until readable.

### Case: XOR with Flag Format

If ciphertext starts with known plaintext (like "flag{"), XOR the first 5 bytes to recover the key.

---

## Tools Summary

| Tool | Purpose | Install |
|------|---------|---------|
| pycryptodome | AES/RSA crypto | pip install pycryptodome |
| gmpy2 | Large number math | pip install gmpy2 |
| sage | Advanced math | Download from sagemath.org |
| hashid | Hash identification | pip install hashid |
| john | Password cracker | apt install john |
| hashcat | GPU hash cracker | Download from hashcat.net |
