---
name: ctf-reverse
description: This skill should be used when solving CTF (Capture The Flag) reverse engineering challenges involving executable files (EXE, ELF, etc.). Triggers include: analyzing packed binaries, bypassing anti-debug, identifying encryption algorithms (TEA, XOR, RC4, AES), extracting hardcoded keys and ciphertext, disassembling with capstone, and reconstructing flag verification logic from assembly.
---

# CTF Reverse Engineering Skill

## Overview

This skill provides a systematic workflow for solving CTF reverse engineering challenges involving executable files (EXE, ELF, etc.). It covers packer detection, anti-debug bypass, algorithm identification, and flag extraction using Python tools.

**Core principle**: Work from the outside in -- identify packer first, then anti-debug, then algorithm, then extract/solve.

---

## Quick Start Checklist

1. Check file type and size (small EXE < 20KB = likely packed)
2. Extract strings -- look for UPX, MPRESS, flags, algorithm hints
3. Unpack if needed (UPX is most common)
4. Re-extract strings after unpacking
5. Find main verification function via string cross-references
6. Identify algorithm (TEA/XOR/AES/RC4/custom)
7. Extract key and ciphertext from code
8. Implement decryption in Python
9. Verify output looks like a valid flag

---

## Step 1: Initial File Identification

```python
import re, struct

filepath = r"challenge.exe"

with open(filepath, "rb") as f:
    data = f.read()

size = len(data)
header = data[:16].hex()
print(f"Size: {size} bytes ({size//1024} KB)")
print(f"Header: {header}")

# Check magic bytes
if data[:2] == b"MZ":
    print("Type: Windows PE executable")
elif data[:4] == b"\x7fELF":
    print("Type: Linux ELF executable")

# Check for packers
for packer in [b"UPX0", b"UPX1", b"MPRESS", b"PEtite", b"FSG"]:
    if packer in data:
        print(f"Packer detected: {packer.decode()}")
```

---

## Step 2: String Extraction

```python
import re

with open(r"challenge.exe", "rb") as f:
    data = f.read()

# Extract all printable ASCII strings (4+ chars)
strings = re.findall(rb"[\x20-\x7e]{4,}", data)
unique = sorted(set(s.decode("latin1") for s in strings))

print("=== All strings ===")
for s in unique:
    print(s)

# Filter for interesting keywords
print("\n=== Interesting strings ===")
keywords = ["flag", "input", "correct", "wrong", "key", "pass",
            "CTF", "UPX", "debug", "anti", "congratu", "pity"]
for s in unique:
    if any(k.lower() in s.lower() for k in keywords):
        print(repr(s))
```

---

## Step 3: UPX Unpacking

**Option A -- using upx.exe tool (recommended):**
```powershell
# Download UPX (Windows)
python -c "
import urllib.request, zipfile, io, shutil, os
url = 'https://github.com/upx/upx/releases/download/v4.2.1/upx-4.2.1-win64.zip'
req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
data = urllib.request.urlopen(req, timeout=30).read()
z = zipfile.ZipFile(io.BytesIO(data))
for name in z.namelist():
    if name.endswith('upx.exe'):
        z.extract(name, '.')
        src = name
        shutil.move(src, 'upx.exe')
        break
print('UPX ready')
"

# Unpack
copy challenge.exe challenge_unpacked.exe
upx.exe -d challenge_unpacked.exe
```

**Option B -- manual UPX unpack in Python:**
```python
# UPX stores original entry point after UPX1 section
# For simple cases, check section headers for original EP
import struct

with open("challenge.exe", "rb") as f:
    data = f.read()

# Parse PE to find OEP stored in UPX stub
e_lfanew = struct.unpack_from("<I", data, 0x3c)[0]
print("PE offset:", hex(e_lfanew))
```

---

## Step 4: PE Structure Analysis

```python
import struct

with open(r"challenge_unpacked.exe", "rb") as f:
    data = f.read()

e_lfanew = struct.unpack_from("<I", data, 0x3c)[0]
pe = e_lfanew

# Machine type
machine = struct.unpack_from("<H", data, pe + 4)[0]
arch = "x64" if machine == 0x8664 else "x86" if machine == 0x14c else hex(machine)
print(f"Architecture: {arch}")

# Entry point
ep_rva = struct.unpack_from("<I", data, pe + 0x18 + 0x10)[0]
print(f"Entry Point RVA: {hex(ep_rva)}")

# Image base (x64)
image_base = struct.unpack_from("<Q", data, pe + 0x18 + 0x18)[0]
print(f"Image Base: {hex(image_base)}")

# Sections
num_sections = struct.unpack_from("<H", data, pe + 6)[0]
opt_size = struct.unpack_from("<H", data, pe + 0x14)[0]
sec_off = pe + 0x18 + opt_size
print(f"\nSections ({num_sections}):")
for i in range(num_sections):
    off = sec_off + i * 40
    name = data[off:off+8].rstrip(b"\x00").decode("ascii", errors="replace")
    vaddr = struct.unpack_from("<I", data, off + 12)[0]
    vsize = struct.unpack_from("<I", data, off + 16)[0]
    raw_off = struct.unpack_from("<I", data, off + 20)[0]
    raw_size = struct.unpack_from("<I", data, off + 24)[0]
    print(f"  {name:8}: VA={hex(vaddr)}, size={hex(vsize)}, raw={hex(raw_off)}")
```

---

## Step 5: Disassembly with Capstone

```python
# Install: pip install capstone
import capstone, struct, re

with open(r"challenge_unpacked.exe", "rb") as f:
    data = f.read()

image_base = 0x140000000  # typical x64 base
text_raw = 0x400          # .text raw offset (adjust per binary)
text_va  = 0x1000         # .text VA (adjust per binary)
code = data[text_raw:text_raw + 0x8000]
base_addr = image_base + text_va

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True

# Disassemble and dump to file
with open("disasm_out.txt", "w", encoding="utf-8") as out:
    for insn in md.disasm(code, base_addr):
        line = f"{hex(insn.address)}: {insn.mnemonic:10} {insn.op_str}"
        out.write(line + "\n")

print("Disassembly written to disasm_out.txt")
```

**Finding string cross-references (xrefs):**
```python
import capstone, re

image_base = 0x140000000
target_rva = 0x90b4  # RVA of the string you want to find refs to

with open("disasm_out.txt") as f:
    lines = f.readlines()

for line in lines:
    if "rip +" in line:
        m = re.search(r"(0x[0-9a-f]+):", line)
        addr_m = re.search(r"rip \+ (0x[0-9a-f]+)", line)
        if m and addr_m:
            insn_addr = int(m.group(1), 16)
            # compute next instruction addr (rough estimate, +7 bytes)
            disp = int(addr_m.group(1), 16)
            target = (insn_addr + 7 + disp) & 0xFFFFFFFF
            target_rva_computed = target - image_base
            if abs(target_rva_computed - target_rva) < 0x20:
                print(line.strip())
```

---

## Step 6: Algorithm Identification

### TEA (Tiny Encryption Algorithm)
**Signature constants to look for in disasm:**
- `0x9e3779b9` -- TEA DELTA
- `0xc6ef3720` -- TEA DELTA * 32 (used as initial sum for decryption)
- Shift left 4, shift right 5 pattern
- 32-iteration loop

**TEA Decrypt (Python):**
```python
def tea_decrypt(v0, v1, key):
    """
    v0, v1: two uint32 ciphertext values
    key: list of 4 uint32 values [k0, k1, k2, k3]
    returns: (decrypted_v0, decrypted_v1)
    """
    DELTA = 0x9e3779b9
    total = (DELTA * 32) & 0xFFFFFFFF
    mask = 0xFFFFFFFF
    for _ in range(32):
        v1 = (v1 - (((v0 << 4) + key[2]) ^ (v0 + total) ^ ((v0 >> 5) + key[3]))) & mask
        v0 = (v0 - (((v1 << 4) + key[0]) ^ (v1 + total) ^ ((v1 >> 5) + key[1]))) & mask
        total = (total - DELTA) & mask
    return v0, v1
```

**XTEA Decrypt:**
```python
def xtea_decrypt(v0, v1, key, rounds=32):
    DELTA = 0x9e3779b9
    mask = 0xFFFFFFFF
    total = (DELTA * rounds) & mask
    for _ in range(rounds):
        v1 = (v1 - (((v0 << 4 ^ v0 >> 5) + v0) ^ (total + key[(total >> 11) & 3]))) & mask
        total = (total - DELTA) & mask
        v0 = (v0 - (((v1 << 4 ^ v1 >> 5) + v1) ^ (total + key[total & 3]))) & mask
    return v0, v1
```

### XOR cipher
```python
def xor_decrypt(data, key):
    if isinstance(key, str):
        key = [ord(c) for c in key]
    elif isinstance(key, int):
        key = [key]
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
```

### RC4
```python
def rc4_decrypt(data, key):
    if isinstance(key, str):
        key = key.encode()
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    result = []
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        result.append(byte ^ S[(S[i] + S[j]) % 256])
    return bytes(result)
```

---

## Step 7: Extract Ciphertext from Binary

```python
# Read dwords from a specific raw offset in the binary
import struct

with open(r"challenge_unpacked.exe", "rb") as f:
    data = f.read()

# Replace with actual offset from disassembly analysis
raw_offset = 0xb100   # example
count = 32            # number of dwords

dwords = struct.unpack_from(f"<{count}I", data, raw_offset)
print("Ciphertext dwords:", [hex(d) for d in dwords])
```

---

## Step 8: Anti-Debug Patterns

Common anti-debug techniques in Windows CTF binaries:

| Technique | API/Pattern | Bypass |
|-----------|-------------|--------|
| IsDebuggerPresent | `call IsDebuggerPresent` then `test eax, eax` | Patch `jnz` to `jz` or NOP |
| CheckRemoteDebuggerPresent | Similar pattern | Same as above |
| NtQueryInformationProcess | ProcessDebugPort query | Patch return value |
| Timing check | `rdtsc` delta comparison | Patch jmp |
| Exception-based | `int 3` / `int 2d` | Ignore exceptions in debugger |

**When analyzing statically (no debugger), anti-debug doesn't matter -- just read the logic directly.**

---

## Step 9: Full Solve Template

```python
import struct, sys
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# ============================================================
# FILL IN: ciphertext dwords from binary
# ============================================================
ciphertext = [
    # paste dwords here, two per TEA block
    # 0xAABBCCDD, 0xEEFF0011, ...
]

# ============================================================
# FILL IN: keys extracted from disassembly
# ============================================================
TEA_KEY = [2, 2, 3, 4]       # 4 uint32 TEA key
XOR_KEY = b"reverse"          # XOR key for post-processing

def tea_decrypt(v0, v1, key):
    DELTA = 0x9e3779b9
    total = (DELTA * 32) & 0xFFFFFFFF
    mask = 0xFFFFFFFF
    for _ in range(32):
        v1 = (v1 - (((v0 << 4) + key[2]) ^ (v0 + total) ^ ((v0 >> 5) + key[3]))) & mask
        v0 = (v0 - (((v1 << 4) + key[0]) ^ (v1 + total) ^ ((v1 >> 5) + key[1]))) & mask
        total = (total - DELTA) & mask
    return v0, v1

# TEA decrypt pairs
decrypted = []
for i in range(0, len(ciphertext), 2):
    v0, v1 = tea_decrypt(ciphertext[i], ciphertext[i+1], TEA_KEY)
    decrypted.extend([v0, v1])

# XOR post-processing
flag_chars = []
for i, dword in enumerate(decrypted):
    b = dword & 0xFF
    xored = b ^ XOR_KEY[i % len(XOR_KEY)]
    flag_chars.append(xored)

flag = "".join(chr(c) if 0x20 <= c < 0x7f else "?" for c in flag_chars)
print("Flag:", flag)
print("Wrapped: flag{" + flag + "}")
```

---

## Decision Tree

```
Start: Got a binary challenge
  |
  +-- Check file size < 20KB?
  |     Yes -> Probably packed
  |           Check for UPX/MPRESS strings
  |           Unpack with upx -d or tool
  |
  +-- Extract strings
  |     Direct flag visible? -> DONE
  |     See algorithm names (TEA/RC4/AES)? -> note it
  |     See anti-debug strings? -> static analysis only
  |
  +-- Disassemble (.text section)
  |     Find main() via entry point
  |     Find verification function via string xrefs
  |     (look for scanf/input/flag string refs)
  |
  +-- Identify algorithm
  |     0x9e3779b9 -> TEA/XTEA
  |     sbox tables -> AES/Serpent
  |     simple XOR loop -> XOR cipher
  |     custom -> analyze loop manually
  |
  +-- Extract key + ciphertext
  |     Key: often hardcoded as immediate values in LEA/MOV
  |     Ciphertext: array initialized near verification function
  |
  +-- Implement decryption in Python
        Test output is printable ASCII
        Format as flag{...} if needed
```

---

## Real Case: ez_arithmetic (TEA + XOR)

**Challenge**: `ez_arithmetic.exe` -- 14KB UPX-packed PE
**Flag**: `flag{203f12f62c9ed69e810f404bd7003ba7}`

**Key findings:**
1. UPX packed (14KB compressed -> 54KB unpacked)
2. Anti-debug: `IsDebuggerPresent` at function start
3. Algorithm: TEA decrypt (DELTA=0x9e3779b9, 32 rounds) followed by XOR with string "reverse"
4. TEA key: `[2, 2, 3, 4]` (4 uint32 values found in disassembly)
5. Ciphertext: 32 dwords hardcoded in main(), initialized before calling decrypt function
6. Expected input length: 32 bytes (0x20)

**Key lesson**: When you see `0x9e3779b9` AND `0xc6ef3720` together, it's TEA decrypt (sum starts at DELTA*32 for decryption). The key is usually found as immediate values in the 4 MOV instructions just before the TEA call.

---

## Common Flag Formats

| Format | Example | When |
|--------|---------|------|
| flag{...} | flag{abc123} | Most CTFs |
| FLAG{...} | FLAG{ABC123} | Some competitions |
| ctf{...} | ctf{abc123} | Less common |
| Raw 32 hex chars | 203f12f6... | Sometimes wrapped: flag{203f...} |
| UUID format | flag{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx} | Seen in some challenges |

---

## Tools Summary

| Tool | Purpose | Install |
|------|---------|---------|
| upx | Unpack UPX | Download upx binary |
| capstone | Disassembler | pip install capstone |
| pefile | PE parsing | pip install pefile |
| angr | Symbolic execution | pip install angr |
| Ghidra | Full decompiler | Free download |
| IDA Free | Disassembler/decompiler | Free version available |
