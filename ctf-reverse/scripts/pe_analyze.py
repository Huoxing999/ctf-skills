"""
CTF Reverse - PE String Extractor + Packer Detector
Usage: python strings_extract.py <exe_path>
"""

import re
import sys
import struct

def extract_strings(filepath, min_len=4):
    with open(filepath, "rb") as f:
        data = f.read()

    strings = re.findall(rb"[\x20-\x7e]{" + str(min_len).encode() + rb",}", data)
    return [s.decode("latin1") for s in strings]


def detect_packer(filepath):
    with open(filepath, "rb") as f:
        data = f.read()

    packers = {
        b"UPX0": "UPX",
        b"UPX1": "UPX",
        b"UPX!": "UPX",
        b"MPRESS1": "MPRESS",
        b"PEtite": "PEtite",
        b"FSG ": "FSG",
        b"Themida": "Themida",
        b"VMProtect": "VMProtect",
    }
    found = []
    for sig, name in packers.items():
        if sig in data and name not in found:
            found.append(name)
    return found


def pe_info(filepath):
    with open(filepath, "rb") as f:
        data = f.read()

    if data[:2] != b"MZ":
        return None

    e_lfanew = struct.unpack_from("<I", data, 0x3c)[0]
    pe = e_lfanew

    machine = struct.unpack_from("<H", data, pe + 4)[0]
    arch = {0x8664: "x64", 0x14c: "x86"}.get(machine, hex(machine))
    ep_rva = struct.unpack_from("<I", data, pe + 0x18 + 0x10)[0]

    num_sections = struct.unpack_from("<H", data, pe + 6)[0]
    opt_size = struct.unpack_from("<H", data, pe + 0x14)[0]
    sec_off = pe + 0x18 + opt_size

    sections = []
    for i in range(num_sections):
        off = sec_off + i * 40
        name = data[off:off+8].rstrip(b"\x00").decode("ascii", errors="replace")
        vaddr = struct.unpack_from("<I", data, off + 12)[0]
        vsize = struct.unpack_from("<I", data, off + 16)[0]
        raw_off = struct.unpack_from("<I", data, off + 20)[0]
        sections.append((name, vaddr, vsize, raw_off))

    return {"arch": arch, "ep_rva": ep_rva, "sections": sections}


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "challenge.exe"

    print(f"=== Analyzing: {path} ===\n")

    # Packer check
    packers = detect_packer(path)
    if packers:
        print(f"[!] Packer(s) detected: {', '.join(packers)}")
        print("    -> Unpack first: upx -d <file>")
    else:
        print("[+] No common packer detected")

    # PE info
    info = pe_info(path)
    if info:
        print(f"\nArchitecture : {info['arch']}")
        print(f"Entry Point  : {hex(info['ep_rva'])}")
        print("\nSections:")
        for name, va, vs, ro in info["sections"]:
            print(f"  {name:8} VA={hex(va)}  size={hex(vs)}  raw_off={hex(ro)}")

    # Strings
    strings = extract_strings(path)
    print(f"\n=== Strings ({len(strings)} total) ===")
    interesting = ["flag", "input", "correct", "wrong", "key", "pass",
                   "CTF", "debug", "congratu", "pity", "hint", "answer"]
    print("Interesting strings:")
    for s in strings:
        if any(k.lower() in s.lower() for k in interesting):
            print(f"  {repr(s)}")

    print("\nAll strings (4+ chars):")
    for s in sorted(set(strings)):
        print(f"  {s}")
