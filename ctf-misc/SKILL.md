---
name: ctf-misc
description: This skill should be used when solving CTF (Capture The Flag) miscellaneous challenges. Triggers include: forensics (PCAP, memory dumps), OSINT, QR codes, barcode, morse code, binary/brainfuck/malbolge esoteric languages, traffic analysis, log analysis, digital forensics, and challenges that don't fit other categories.
---

# CTF Miscellaneous

## Overview

This skill covers CTF challenges that don't fit neatly into web, crypto, reverse, or stego categories. It includes forensics, OSINT, esoteric languages, traffic analysis, and general puzzle-solving.

**Core principle**: Misc challenges are often about "thinking outside the box" -- the flag may be hidden in unexpected places.

---

## Quick Start Checklist

1. Examine the file type and structure
2. Check for hidden data (strings, metadata, appended data)
3. Identify the encoding/language used
4. Apply the appropriate decoding/extraction method
5. Think about what makes the challenge "misc"

---

## Category 1: File Forensics

### File Type Analysis

```python
import struct, os

def file_analysis(filepath):
    """Analyze file type, check for hidden data"""
    with open(filepath, 'rb') as f:
        data = f.read()
    
    size = len(data)
    print(f"File: {os.path.basename(filepath)}")
    print(f"Size: {size} bytes ({size/1024:.1f} KB)")
    print(f"Header (hex): {data[:32].hex()}")
    print(f"Footer (hex): {data[-32:].hex()}")
    
    # Magic bytes identification
    magic = {
        b'\x89PNG': 'PNG Image',
        b'\xff\xd8\xff': 'JPEG Image',
        b'GIF8': 'GIF Image',
        b'BM': 'BMP Image',
        b'PK\x03\x04': 'ZIP Archive',
        b'\x1f\x8b': 'GZIP Archive',
        b'Rar': 'RAR Archive',
        b'7z': '7z Archive',
        b'%PDF': 'PDF Document',
        b'\x7fELF': 'ELF Binary',
        b'MZ': 'PE Executable',
        b'\x00\x00\x00\x1c\x66\x74\x79\x70': 'MP4 Video',
        b'\x00\x00\x00\x18\x66\x74\x79\x70': 'MP4 Video',
        b'RIFF': 'RIFF Container (WAV/AVI)',
        b'OggS': 'OGG Container',
    }
    
    for sig, name in magic.items():
        if data.startswith(sig):
            print(f"Detected type: {name}")
            break
    
    # Check for appended data (multiple file signatures)
    print("\nEmbedded signatures:")
    for sig, name in magic.items():
        pos = data.find(sig)
        if pos > 0:
            print(f"  {name} found at offset {pos} (0x{pos:x})")
    
    # Check entropy (high entropy = encrypted/compressed)
    from collections import Counter
    freq = Counter(data)
    entropy = -sum((c/size) * __import__('math').log2(c/size) for c in freq.values())
    print(f"\nEntropy: {entropy:.2f} bits/byte (high > 7.5 = encrypted/compressed)")
```

### PCAP Network Analysis

```python
# With scapy
from scapy.all import *

def analyze_pcap(pcap_file):
    packets = rdpcap(pcap_file)
    print(f"Total packets: {len(packets)}")
    
    # Extract HTTP data
    for pkt in packets:
        if pkt.haslayer('TCP') and pkt.haslayer('Raw'):
            raw = pkt['Raw'].load.decode('utf-8', errors='ignore')
            if 'flag' in raw.lower() or 'password' in raw.lower():
                print(f"\n[INTERESTING] {pkt['IP'].src} -> {pkt['IP'].dst}")
                print(f"  {raw[:500]}")
    
    # Extract DNS queries
    for pkt in packets:
        if pkt.haslayer('DNS'):
            if pkt['DNS'].qr == 0:  # query
                qname = pkt['DNS'].qd.qname.decode()
                print(f"[DNS] {qname}")
    
    # Extract credentials from FTP/HTTP
    for pkt in packets:
        if pkt.haslayer('TCP') and pkt.haslayer('Raw'):
            raw = pkt['Raw'].load.decode('utf-8', errors='ignore')
            if 'USER' in raw or 'PASS' in raw or 'Authorization' in raw:
                print(f"[AUTH] {raw.strip()}")

# Without scapy - using tshark CLI
# tshark -r capture.pcap -Y "http" -T fields -e http.request.uri -e http.file_data
# tshark -r capture.pcap -Y "dns" -T fields -e dns.qry.name
# tshark -r capture.pcap -Y "ftp" -T fields -e ftp.request.command -e ftp.request.arg
```

### Memory Forensics (Volatility)

```bash
# Basic volatility workflow
vol.py -f memory.raw imageinfo                    # Identify OS profile
vol.py -f memory.raw --profile=Win7SP1x64 pslist   # List processes
vol.py -f memory.raw --profile=Win7SP1x64 psscan   # Scan for hidden processes
vol.py -f memory.raw --profile=Win7SP1x64 netscan  # Network connections
vol.py -f memory.raw --profile=Win7SP1x64 filescan # Open files
vol.py -f memory.raw --profile=Win7SP1x64 cmdscan  # Command history
vol.py -f memory.raw --profile=Win7SP1x64 consoles  # Console output
vol.py -f memory.raw --profile=Win7SP1x64 dumpregistry -o output/  # Registry
vol.py -f memory.raw --profile=Win7SP1x64 hashdump # Password hashes
vol.py -f memory.raw --profile=Win7SP1x64 strings  # Memory strings

# Extract files from memory
vol.py -f memory.raw --profile=Win7SP1x64 memdump -p <PID> -D output/
```

---

## Category 2: Esoteric Languages

### Brainfuck

```python
def brainfuck(code):
    """Brainfuck interpreter"""
    # Clean code (only valid commands)
    code = ''.join(c for c in code if c in '><+-.,[]')
    tape = [0] * 30000
    ptr = 0
    output = []
    i = 0
    
    # Build bracket map for jumps
    bracket_map = {}
    stack = []
    for pos, cmd in enumerate(code):
        if cmd == '[':
            stack.append(pos)
        elif cmd == ']':
            if stack:
                start = stack.pop()
                bracket_map[start] = pos
                bracket_map[pos] = start
    
    while i < len(code):
        cmd = code[i]
        if cmd == '>': ptr += 1
        elif cmd == '<': ptr -= 1
        elif cmd == '+': tape[ptr] = (tape[ptr] + 1) % 256
        elif cmd == '-': tape[ptr] = (tape[ptr] - 1) % 256
        elif cmd == '.':
            output.append(chr(tape[ptr]))
        elif cmd == ',':
            pass  # No input
        elif cmd == '[':
            if tape[ptr] == 0:
                i = bracket_map[i]
        elif cmd == ']':
            if tape[ptr] != 0:
                i = bracket_map[i]
        i += 1
    
    return ''.join(output)
```

### Morse Code

```python
MORSE = {
    '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
    '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
    '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
    '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
    '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
    '--..': 'Z', '-----': '0', '.----': '1', '..---': '2', '...--': '3',
    '....-': '4', '.....': '5', '-....': '6', '--...': '7', '---..': '8',
    '----.': '9', '.-.-.-': '.', '--..--': ',', '..--..': '?', '.----.': "'",
    '-.-.--': '!', '-..-.': '/', '-.--.': '(', '-.--.-': ')', '.-...': '&',
    '---...': ':', '-.-.-.': ';', '-...-': '=', '.-.-.': '+', '-....-': '-',
    '..--.-': '_', '.-..-.': '"', '...-..-': '$', '.--.-.': '@',
    '/': ' '
}

def morse_decode(morse_text):
    """Decode Morse code (supports .-/. / -.- / .-. / .-. / .-..)"""
    words = morse_text.strip().split(' / ')  # word separator
    # Also try '  ' (double space) and '|' as separators
    if len(words) == 1:
        words = morse_text.strip().split('  ')
    if len(words) == 1:
        words = morse_text.strip().split(' | ')
    
    result = []
    for word in words:
        letters = word.strip().split(' ')
        decoded_word = ''
        for letter in letters:
            letter = letter.strip()
            if letter in MORSE:
                decoded_word += MORSE[letter]
        result.append(decoded_word)
    
    return ' '.join(result)

# Also try reversed morse (some CTFs reverse the mapping)
def morse_encode(text):
    reverse_morse = {v: k for k, v in MORSE.items()}
    return ' '.join(reverse_morse.get(c.upper(), '?') for c in text)
```

### Binary/Octal/Decimal Encoding

```python
def binary_decode(data):
    """Decode binary strings (8-bit ASCII)"""
    # Handle space-separated: "01000110 01001100 01000001 01000111"
    if ' ' in data:
        parts = data.split()
    else:
        # Handle continuous: "01000110010011000100000101000111"
        parts = [data[i:i+8] for i in range(0, len(data), 8)]
    
    result = ''.join(chr(int(b, 2)) for b in parts if len(b) == 8)
    return result

def octal_decode(data):
    """Decode octal strings"""
    parts = data.replace(' ', '').split('\\0')[1:]  # handle \0xxx format
    if not parts:
        parts = data.split()
    return ''.join(chr(int(p, 8)) for p in parts)

def decimal_decode(data):
    """Decode decimal ASCII values"""
    parts = data.replace(',', ' ').replace('\\', ' ').split()
    return ''.join(chr(int(p)) for p in parts)
```

### Ook! Language

```python
def ook_to_brainfuck(ook_code):
    """Convert Ook! to Brainfuck"""
    import re
    # Replace Ook. Ook? -> >
    # Replace Ook? Ook. -> <
    # Replace Ook! Ook. -> +
    # Replace Ook. Ook! -> -
    # Replace Ook! Ook! -> [
    # Replace Ook? Ook? -> ]
    replacements = [
        ('Ook. Ook?', '>'), ('Ook? Ook.', '<'),
        ('Ook! Ook.', '+'), ('Ook. Ook!', '-'),
        ('Ook! Ook!', '['), ('Ook? Ook?', ']'),
        ('Ook! Ook?', '.'), ('Ook? Ook!', ','),
    ]
    bf = ook_code
    for old, new in replacements:
        bf = bf.replace(old, new)
    # Remove remaining Ook tokens
    bf = re.sub(r'Ook[.!?]\s*', '', bf)
    return bf
```

---

## Category 3: QR Code & Barcode

```python
# QR Code generation and reading
# pip install qrcode pyzbar pillow

from PIL import Image
import qrcode

def generate_qr(data, output_path='qr.png'):
    qr = qrcode.QRCode(version=1, box_size=10, border=2)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color='black', back_color='white')
    img.save(output_path)
    print(f"QR saved to {output_path}")

def read_qr(image_path):
    from pyzbar.pyzbar import decode
    img = Image.open(image_path)
    results = decode(img)
    for result in results:
        print(f"Type: {result.type}, Data: {result.data.decode()}")
```

---

## Category 4: Log Analysis

```bash
# Extract interesting entries from access logs
grep -iE "flag|admin|passwd|union|select|exec|system|eval|alert|script" access.log

# Find unique IPs
awk '{print $1}' access.log | sort | uniq -c | sort -rn | head -20

# Extract SQL injection attempts
grep -iE "union.*select|or.*1.*=.*1|'--|;drop|;delete" access.log

# Extract potential passwords
grep -iE "password|passwd|pwd" access.log

# Apache combined log format parser
awk '{
  split($7, path, "?")
  if (path[1] ~ /\.(php|asp|jsp|py)/) {
    print $1, $4, $5, $6, $7
  }
}' access.log | head -50

# Extract POST data from logs
grep "POST" access.log | grep -oE 'body=[^ ]*' | sort | uniq
```

---

## Category 5: Steganography in Non-Image Files

### Audio Steganography

```python
# WAV file steganography - check for hidden data in audio
import struct

def analyze_wav(filepath):
    with open(filepath, 'rb') as f:
        data = f.read()
    
    # Check RIFF header
    print(f"Header: {data[:12]}")
    
    # Check for text markers
    markers = [b'LIST', b'INFO', b'ISFT', b'ISMP', b'ISBJ']
    for marker in markers:
        pos = data.find(marker)
        if pos >= 0:
            chunk_data = data[pos:pos+200]
            print(f"Found {marker} at offset {pos}: {chunk_data[:100]}")
    
    # LSB of audio samples
    # Read PCM data and extract LSBs
    if data[:4] == b'RIFF' and data[8:12] == b'WAVE':
        # Find data chunk
        pos = 12
        while pos < len(data):
            chunk_id = data[pos:pos+4]
            chunk_size = struct.unpack('<I', data[pos+4:pos+8])[0]
            if chunk_id == b'data':
                audio_data = data[pos+8:pos+8+min(chunk_size, 10000)]
                lsb_bits = [b & 1 for b in audio_data[:200]]
                # Convert bits to bytes
                lsb_bytes = []
                for i in range(0, len(lsb_bits) - 7, 8):
                    byte = 0
                    for j in range(8):
                        byte = (byte << 1) | lsb_bits[i+j]
                    lsb_bytes.append(byte)
                lsb_text = bytes(lsb_bytes)
                print(f"LSB text (first 50 bytes): {lsb_text[:50]}")
                break
            pos += 8 + chunk_size
```

### PDF Steganography

```python
# PDF analysis - check for hidden text, embedded files
import re

def analyze_pdf(filepath):
    with open(filepath, 'rb') as f:
        data = f.read()
    
    # Check PDF header
    print(f"Header: {data[:20]}")
    
    # Extract text streams
    streams = re.findall(rb'stream\r?\n(.*?)\r?\nendstream', data, re.DOTALL)
    for i, stream in enumerate(streams):
        try:
            import zlib
            decoded = zlib.decompress(stream)
            text = decoded.decode('utf-8', errors='ignore')
            if 'flag' in text.lower() or any(c.isalpha() for c in text):
                print(f"\nStream {i}: {text[:500]}")
        except: pass
    
    # Check for embedded files
    embedded = re.findall(rb'/EmbeddedFile', data)
    if embedded:
        print(f"Found {len(embedded)} embedded files")
    
    # Check for JavaScript
    js = re.findall(rb'/JavaScript', data)
    if js:
        print(f"Found {len(js)} JavaScript entries")
    
    # Check for hidden text (white/invisible)
    text_patterns = re.findall(rb'\(([^)]{5,})\)', data)
    for t in text_patterns:
        try:
            decoded = t.decode('utf-8', errors='ignore')
            if any(c.isalpha() for c in decoded):
                print(f"Text: {decoded[:100]}")
        except: pass
```

---

## Category 6: OSINT (Open Source Intelligence)

```bash
# Google Dorking for CTF
# site:target.com filetype:pdf
# site:target.com filetype:txt
# site:target.com inurl:admin
# site:target.com intitle:"index of"
# site:target.com ext:bak
# "flag{" site:target.com

# Wayback Machine
# https://web.archive.org/web/*/http://target.com/*

# DNS enumeration
# dig target.com ANY
# dig target.com TXT
# nslookup -type=any target.com
# subfinder -d target.com

# Social media / profile search
# Check GitHub, Twitter, LinkedIn for usernames from the challenge
```

---

## Category 7: Coordinate / Geolocation

```python
def decode_coordinates(lat_str, lon_str):
    """Common CTF coordinate puzzle decoder"""
    # DMS (Degrees Minutes Seconds) to decimal
    def dms_to_decimal(dms):
        parts = dms.replace('°', ' ').replace("'", ' ').replace('"', ' ').split()
        d, m, s = float(parts[0]), float(parts[1]), float(parts[2]) if len(parts) > 2 else 0
        direction = parts[-1].upper() if parts[-1][-1] in 'NSEW' else ''
        decimal = d + m/60 + s/3600
        if direction in ['S', 'W']:
            decimal = -decimal
        return decimal
    
    lat = dms_to_decimal(lat_str)
    lon = dms_to_decimal(lon_str)
    print(f"Google Maps: https://www.google.com/maps?q={lat},{lon}")
```

---

## Decision Tree

```
Start: Got a misc challenge
  |
  +-- Network capture (PCAP)?
  |     Yes -> Extract HTTP/DNS/FTP data
  |            Look for credentials, flag in cleartext
  |            Follow TCP streams for full conversations
  |
  +-- Memory dump?
  |     Yes -> Use Volatility framework
  |            Process list, command history, strings, files
  |
  +-- Esoteric language (brainfuck/Ook/malbolge)?
  |     Yes -> Identify language from syntax
  |            Convert to Brainfuck if needed, then interpret
  |
  +-- Morse code / binary / octal?
  |     Yes -> Decode using standard tables
  |
  +-- QR code / barcode?
  |     Yes -> Scan/decode with appropriate tool
  |
  +-- Audio file?
  |     Yes -> Spectrogram analysis, LSB extraction, DTMF decoding
  |
  +-- Log file?
  |     Yes -> Grep for flag, anomalies, SQL injection attempts
  |
  +-- PDF?
  |     Yes -> Extract streams, check for hidden text/embedded files
  |
  +-- Forensics image?
        Yes -> File carving, metadata analysis, timeline reconstruction
```

---

## Tools Summary

| Tool | Purpose | Install |
|------|---------|---------|
| volatility3 | Memory forensics | pip install volatility3 |
| scapy | Packet analysis | pip install scapy |
| tshark | CLI packet capture | apt install tshark |
| binwalk | Firmware analysis | pip install binwalk |
| foremost | File carving | apt install foremost |
| sleuthkit | Disk forensics | apt install sleuthkit |
| exiftool | Metadata extraction | apt install exiftool |
| steghide | Audio/image stego | apt install steghide |
| pyzbar | QR/barcode reading | pip install pyzbar |
| pillow | Image processing | pip install pillow |
