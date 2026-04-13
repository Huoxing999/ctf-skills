---
name: ctf-stego
description: This skill should be used when solving CTF (Capture The Flag) steganography challenges involving hidden data in images, files, or encoded content. Triggers include: extracting flags from images, analyzing file headers/footers, decoding base64, finding embedded files, analyzing EXIF metadata, or identifying hidden data through LSB, binwalk, or other steganography techniques.
---

# CTF Steganography

## Overview

This skill provides systematic workflows for solving CTF steganography challenges. It covers common techniques for extracting hidden flags from various file types, with emphasis on images (PNG, JPEG, BMP) and encoded data streams.

## Quick Start

When encountering a steganography challenge, follow this systematic approach:

1. **Basic Observation** - Always view the file (open image, read text, check file structure)
2. **File Analysis** - Examine headers, footers, and file structure for anomalies
3. **Metadata Extraction** - Check EXIF, comments, and embedded metadata
4. **Common Decoding** - Try base64, hex, ROT, and other simple encodings
5. **Advanced Techniques** - LSB, binwalk, strings, and binary analysis

## Common Techniques

### 1. Visual Inspection (ALWAYS FIRST)

Before diving into analysis, always view the file directly:
- For images: Use `open_result_view` or open in image viewer to check for visible text, QR codes, or obvious patterns
- For text files: Read the raw content for base64, hex, or encoded strings
- This catches "observation challenges" where flags are plain visible (like the cat image example)

**Example:**
```python
# Decode base64 to image, then view it
import base64
with open('attachment.txt', 'r') as f:
    data = f.read().replace('data:image/jpeg;base64,', '')
    with open('output.jpg', 'wb') as out:
        out.write(base64.b64decode(data))
```

### 2. File Structure Analysis

Check for:
- Extra data after file end markers (JPEG ends with `FF D9`)
- Embedded files (ZIP, PNG, etc. hidden after valid file data)
- Multiple file signatures in single file

**PowerShell commands:**
```powershell
# Check file header and footer
$bytes = [System.IO.File]::ReadAllBytes("file.jpg")
$header = ($bytes[0..15] | ForEach-Object { "{0:X2}" -f $_ }) -join " "
$footer = ($bytes[($bytes.Length-20)..($bytes.Length-1)] | ForEach-Object { "{0:X2}" -f $_ }) -join " "

# Find end markers (e.g., JPEG FF D9)
for ($i = 0; $i -lt $bytes.Length - 1; $i++) {
    if ($bytes[$i] -eq 0xFF -and $bytes[$i+1] -eq 0xD9) {
        Write-Host "FF D9 at offset $i"
    }
}
```

### 3. Strings Extraction

Extract printable strings from binary files:
```powershell
$bytes = [System.IO.File]::ReadAllBytes("file.bin")
$text = [System.Text.Encoding]::Latin1.GetString($bytes)
$matches = [regex]::Matches($text, '[\x20-\x7E]{6,}')
$matches | ForEach-Object { $_.Value } | Select-Object -Unique
```

Search for flag patterns:
- `flag{...}`, `FLAG{...}`, `ctf{...}`
- Base64 patterns (A-Za-z0-9+/= with padding)
- Hex strings

### 4. Common Encoding Schemes

**Base64:**
- Pattern: `[A-Za-z0-9+/=]{20,}` ending with `=`, `==`
- Decode using `base64 -d` or `[Convert]::FromBase64String()`

**Hex:**
- Pattern: `[0-9A-Fa-f]{8,}`
- Decode using `xxd -r -p` or convert bytes

**ROT13 / Caesar:**
- Try ROT13 on extracted strings
- Common for simple text puzzles

### 5. Image Steganography Techniques

**LSB (Least Significant Bit):**
- Hidden data in the lowest bit of pixel values
- Tools: `steghide`, `zsteg`, `stegsolve`

**EXIF Metadata:**
- Use `exiftool` to check for hidden comments
- Look for `Comment`, `Description`, or custom tags

**Color Channel Analysis:**
- Separate RGB channels to reveal hidden text
- Check for patterns in specific color planes

**JPEG Comments:**
- Search for `FF FE` markers (JPEG comment segment)
- Extract comment data between marker and length bytes

### 6. Embedded Files

**Binwalk:**
- Scan for embedded filesystems or files
```bash
binwalk -e file.jpg
```

**ZIP in Image (Polyglot):**
- Some files are valid images AND valid ZIPs
- Try extracting with `unzip` or Python's `zipfile`

## Decision Tree

Start with the simplest method first:

```
1. Is it an image file?
   Yes -> View image directly
          Flag visible? -> DONE
          No -> Check EXIF metadata
                Found comment? -> DONE
                No -> Extract strings
                      Found strings? -> Decode -> DONE
                      No -> LSB analysis (steghide/zsteg)
                            No -> Binwalk (embedded files)

2. Is it a text/encoded file?
   -> Try base64 decode first
   -> Try hex decode
   -> Try ROT13/Caesar cipher
```

## Common File Signatures

Remember these magic bytes:
- JPEG: `FF D8 FF`
- PNG: `89 50 4E 47`
- ZIP: `50 4B 03 04`
- PDF: `25 50 44 46`

## References

This skill references common CTF steganography tools and techniques:
- **steghide**: Hides and extracts data from images/audio with password
- **zsteg**: Detects and extracts hidden data from PNG/BMP files
- **binwalk**: Firmware analysis, extracts embedded files
- **exiftool**: Reads/writes EXIF metadata from images
- **strings**: Extracts printable strings from binary files

## Resources

### scripts/
This skill may include Python scripts for:
- Base64 encoding/decoding batch operations
- LSB extraction algorithms
- Color channel separation
- Automated string extraction

### references/
Documentation on:
- JPEG/PNG file format specifications
- Common CTF steganography techniques
- Tool usage guides (steghide, zsteg, binwalk)
- Encoding/decoding references

### assets/
No assets needed for this skill.

---

**Remember:** Always start with visual inspection! Many steganography challenges are simple observation puzzles (like the cat image with visible flag).

