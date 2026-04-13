"""
CTF Reverse - Disassembly Helper
Usage: python disasm_helper.py <exe_path> [raw_offset] [length]
Requires: pip install capstone
"""

import capstone
import struct
import sys
import re


def disasm_section(filepath, raw_offset, size, base_addr, output_file=None):
    with open(filepath, "rb") as f:
        f.seek(raw_offset)
        code = f.read(size)

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True

    lines = []
    for insn in md.disasm(code, base_addr):
        line = f"{hex(insn.address)}: {insn.mnemonic:10} {insn.op_str}"
        lines.append(line)

    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        print(f"Written {len(lines)} instructions to {output_file}")
    else:
        for l in lines:
            print(l)

    return lines


def find_string_refs(disasm_lines, image_base, target_rva, tolerance=0x20):
    """Find instructions that reference a specific RVA (e.g., a string)."""
    refs = []
    for line in disasm_lines:
        if "rip +" in line:
            addr_m = re.search(r"(0x[0-9a-f]+):", line)
            disp_m = re.search(r"rip \+ (0x[0-9a-f]+)", line)
            if addr_m and disp_m:
                insn_addr = int(addr_m.group(1), 16)
                disp = int(disp_m.group(1), 16)
                # Approximate: assume instruction size 7 bytes
                target = (insn_addr + 7 + disp) - image_base
                if abs(target - target_rva) < tolerance:
                    refs.append(line.strip())
    return refs


def find_constants(disasm_lines, constants):
    """Find instructions containing specific constant values (e.g., crypto constants)."""
    results = []
    for const in constants:
        hex_str = hex(const)
        for line in disasm_lines:
            if hex_str in line.lower():
                results.append((const, line.strip()))
    return results


if __name__ == "__main__":
    filepath = sys.argv[1] if len(sys.argv) > 1 else "challenge_unpacked.exe"

    # Auto-detect PE info
    with open(filepath, "rb") as f:
        data = f.read()

    e_lfanew = struct.unpack_from("<I", data, 0x3c)[0]
    pe = e_lfanew
    machine = struct.unpack_from("<H", data, pe + 4)[0]
    image_base = struct.unpack_from("<Q", data, pe + 0x18 + 0x18)[0] if machine == 0x8664 else \
                 struct.unpack_from("<I", data, pe + 0x18 + 0x1c)[0]
    ep_rva = struct.unpack_from("<I", data, pe + 0x18 + 0x10)[0]

    # Find .text section
    num_sections = struct.unpack_from("<H", data, pe + 6)[0]
    opt_size = struct.unpack_from("<H", data, pe + 0x14)[0]
    sec_off = pe + 0x18 + opt_size
    text_raw = text_va = text_size = 0
    for i in range(num_sections):
        off = sec_off + i * 40
        name = data[off:off+8].rstrip(b"\x00").decode("ascii", errors="replace")
        if name == ".text":
            text_va = struct.unpack_from("<I", data, off + 12)[0]
            text_size = struct.unpack_from("<I", data, off + 16)[0]
            text_raw = struct.unpack_from("<I", data, off + 20)[0]
            break

    print(f"Image base: {hex(image_base)}")
    print(f"Entry point RVA: {hex(ep_rva)}")
    print(f".text: raw={hex(text_raw)}, VA={hex(text_va)}, size={hex(text_size)}")
    print(f"Disassembling {text_size} bytes from .text...")

    lines = disasm_section(
        filepath,
        text_raw,
        text_size,
        image_base + text_va,
        output_file="disasm_out.txt"
    )

    # Search for common crypto constants
    crypto_consts = [
        (0x9e3779b9, "TEA/XTEA DELTA"),
        (0xc6ef3720, "TEA sum_init (DELTA*32)"),
        (0x61c88647, "XTEA neg_DELTA"),
        (0x67452301, "MD5/SHA1 init"),
        (0xefcdab89, "MD5/SHA1 init"),
        (0x9908b0df, "MT19937 constant"),
    ]
    print("\n=== Crypto constant search ===")
    found = find_constants(lines, [c[0] for c in crypto_consts])
    if found:
        for const, line in found:
            name = next(n for c, n in crypto_consts if c == const)
            print(f"  [{name}] {line}")
    else:
        print("  No common crypto constants found")
