"""
CTF Reverse - TEA/XTEA Solver Template
Usage: fill in CIPHERTEXT and KEYS, then run with python tea_solve.py
"""

import sys
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# ============================================================
# FILL IN: ciphertext dwords extracted from binary (pairs for TEA)
# ============================================================
CIPHERTEXT = [
    # example from ez_arithmetic:
    0xa98b3a76, 0xdd0b2fc6,
    0xe0254f0f, 0x704361ac,
    0xbcbe9a29, 0x376f45b3,
    0x9a7c96fd, 0x3038c3dc,
    0xedf4a0cd, 0x84e389f7,
    0xa5fff9a9, 0xe9e9d9b9,
    0xe87e5cd1, 0x2c77fbff,
    0x91c614a2, 0xff3e98e8,
    0xccb94be7, 0xa9d09059,
    0x00ae7de3, 0xfc440d0a,
    0xc6040ba2, 0xea1ec60a,
    0xaee31dc7, 0xce776b97,
    0x1bdd1045, 0x597d6b00,
    0x3c6da860, 0x232f5590,
    0xd44c94db, 0x757b4cec,
    0xca98f91a, 0xeb235973,
]

# FILL IN: TEA key (4 uint32 values)
TEA_KEY = [2, 2, 3, 4]

# FILL IN: post-XOR key (string or bytes, set to None to skip)
XOR_KEY = b"reverse"

# FILL IN: expected flag length (number of characters)
FLAG_LEN = 32


# ---- Algorithm implementations ----

def tea_decrypt(v0, v1, key):
    """Standard TEA decryption, 32 rounds."""
    DELTA = 0x9e3779b9
    total = (DELTA * 32) & 0xFFFFFFFF
    mask = 0xFFFFFFFF
    for _ in range(32):
        v1 = (v1 - (((v0 << 4) + key[2]) ^ (v0 + total) ^ ((v0 >> 5) + key[3]))) & mask
        v0 = (v0 - (((v1 << 4) + key[0]) ^ (v1 + total) ^ ((v1 >> 5) + key[1]))) & mask
        total = (total - DELTA) & mask
    return v0, v1


def xtea_decrypt(v0, v1, key, rounds=32):
    """XTEA decryption."""
    DELTA = 0x9e3779b9
    mask = 0xFFFFFFFF
    total = (DELTA * rounds) & mask
    for _ in range(rounds):
        v1 = (v1 - (((v0 << 4 ^ v0 >> 5) + v0) ^ (total + key[(total >> 11) & 3]))) & mask
        total = (total - DELTA) & mask
        v0 = (v0 - (((v1 << 4 ^ v1 >> 5) + v1) ^ (total + key[total & 3]))) & mask
    return v0, v1


def xor_bytes(data, key):
    """XOR data with cyclic key."""
    if isinstance(key, str):
        key = key.encode()
    elif isinstance(key, int):
        key = bytes([key])
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


# ---- Main solve ----

def solve():
    # TEA decrypt pairs
    decrypted = []
    for i in range(0, len(CIPHERTEXT), 2):
        v0, v1 = tea_decrypt(CIPHERTEXT[i], CIPHERTEXT[i+1], TEA_KEY)
        decrypted.extend([v0, v1])

    # Extract low bytes
    raw_bytes = bytes(d & 0xFF for d in decrypted[:FLAG_LEN])
    print("Raw bytes (hex):", raw_bytes.hex())
    print("Raw bytes (ascii):", "".join(chr(b) if 0x20 <= b < 0x7f else "." for b in raw_bytes))

    # XOR post-processing
    if XOR_KEY:
        final = xor_bytes(raw_bytes, XOR_KEY)
    else:
        final = raw_bytes

    flag_str = "".join(chr(b) if 0x20 <= b < 0x7f else "?" for b in final)
    print("\n=== RESULT ===")
    print("Flag input  :", flag_str)
    print("flag{...}   : flag{" + flag_str + "}")


if __name__ == "__main__":
    solve()
