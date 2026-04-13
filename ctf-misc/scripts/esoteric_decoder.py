#!/usr/bin/env python3
"""
CTF Misc Toolkit - 杂项解题工具集
Usage: python3 esoteric_decoder.py <input_file_or_string>
"""
import sys, re, os

# ===== Brainfuck =====
def brainfuck(code):
    code = ''.join(c for c in code if c in '><+-.,[]')
    tape, ptr, output, i = [0]*30000, 0, [], 0
    bracket_map, stack = {}, []
    for pos, cmd in enumerate(code):
        if cmd == '[': stack.append(pos)
        elif cmd == ']':
            if stack: start = stack.pop(); bracket_map[start] = pos; bracket_map[pos] = start
    while i < len(code):
        c = code[i]
        if c == '>': ptr += 1
        elif c == '<': ptr -= 1
        elif c == '+': tape[ptr] = (tape[ptr]+1) % 256
        elif c == '-': tape[ptr] = (tape[ptr]-1) % 256
        elif c == '.': output.append(chr(tape[ptr]))
        elif c == '[' and tape[ptr] == 0: i = bracket_map[i]
        elif c == ']' and tape[ptr] != 0: i = bracket_map[i]
        i += 1
    return ''.join(output)

# ===== Morse Code =====
MORSE = {'.-':'A','-...':'B','-.-.':'C','-..':'D','.':'E','..-.':'F',
    '--.':'G','....':'H','..':'I','.---':'J','-.-':'K','.-..':'L',
    '--':'M','-.':'N','---':'O','.--.':'P','--.-':'Q','.-.':'R',
    '...':'S','-':'T','..-':'U','...-':'V','.--':'W','-..-':'X',
    '-.--':'Y','--..':'Z','-----':'0','.----':'1','..---':'2',
    '...--':'3','....-':'4','.....':'5','-....':'6','--...':'7',
    '---..':'8','----.': '9','/':' '}

def morse_decode(text):
    # Try different word separators
    for sep in [' / ', '  ', ' | ', '   ']:
        if sep in text:
            words = text.strip().split(sep)
            result = []
            for w in words:
                letters = w.strip().split()
                decoded = ''.join(MORSE.get(l, '?') for l in letters if l.strip())
                result.append(decoded)
            return ' '.join(result)
    # Single word
    return ''.join(MORSE.get(l, '?') for l in text.strip().split() if l.strip())

# ===== Binary =====
def binary_decode(text):
    text = text.strip()
    parts = text.split() if ' ' in text else [text[i:i+8] for i in range(0, len(text), 8)]
    return ''.join(chr(int(b, 2)) for b in parts if len(b) == 8)

# ===== Decimal ASCII =====
def decimal_decode(text):
    nums = re.findall(r'\d+', text)
    return ''.join(chr(int(n)) for n in nums if 0 < int(n) < 256)

# ===== Hex ASCII =====
def hex_decode(text):
    text = re.sub(r'\s+', '', text)
    if len(text) % 2 != 0: return None
    try: return bytes.fromhex(text).decode('utf-8', errors='ignore')
    except: return None

# ===== Ook! =====
def ook_decode(text):
    bf = text
    for old, new in [('Ook. Ook?', '>'), ('Ook? Ook.', '<'), ('Ook! Ook.', '+'),
                     ('Ook. Ook!', '-'), ('Ook! Ook!', '['), ('Ook? Ook?', ']'),
                     ('Ook! Ook?', '.'), ('Ook? Ook!', ',')]:
        bf = bf.replace(old, new)
    bf = re.sub(r'Ook[.!?]\s*', '', bf)
    return brainfuck(bf)

# ===== Auto-detect =====
def auto_decode(text):
    text = text.strip()
    
    # Binary: only 0 and 1, length multiple of 8
    if re.fullmatch(r'[01\s]+', text) and len(text.replace(' ','')) % 8 == 0:
        result = binary_decode(text)
        print(f"[BINARY] {result}")
        return result
    
    # Morse: dots and dashes
    if re.fullmatch(r'[\.\-\s/|]+', text):
        result = morse_decode(text)
        print(f"[MORSE] {result}")
        return result
    
    # Brainfuck
    if re.fullmatch(r'[><+\-\.,\[\]\s]+', text) and '[' in text:
        result = brainfuck(text)
        print(f"[BRAINFUCK] {result}")
        return result
    
    # Ook!
    if 'Ook' in text:
        result = ook_decode(text)
        print(f"[OOK] {result}")
        return result
    
    # Hex
    if re.fullmatch(r'[0-9a-fA-F\s]+', text) and len(text.replace(' ','')) >= 8:
        result = hex_decode(text)
        if result and result.isprintable():
            print(f"[HEX] {result}")
            return result
    
    # Decimal
    if re.fullmatch(r'[\d\s,]+', text):
        nums = [int(x) for x in re.findall(r'\d+', text)]
        if all(0 < n < 256 for n in nums):
            result = decimal_decode(text)
            if result.isprintable():
                print(f"[DECIMAL] {result}")
                return result
    
    print("[UNKNOWN] Could not auto-detect, trying all decoders...")
    print(f"  Binary: {binary_decode(text)}")
    print(f"  Decimal: {decimal_decode(text)}")
    return text

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 esoteric_decoder.py <input_file_or_string>")
        print("Examples:")
        print("  python3 esoteric_decoder.py '++++++++[>++++[>++>+++>+++>+<<<<-]>+>+>->>+[<]<-]'")
        print("  python3 esoteric_decoder.py '.... . .-.. .-.. ---'")
        print("  python3 esoteric_decoder.py '01000110 01001100 01000001 01000111'")
        sys.exit(1)
    
    input_data = sys.argv[1]
    
    # Read from file if path exists
    if os.path.exists(input_data):
        with open(input_data, 'r') as f:
            input_data = f.read()
    
    print(f"Input: {input_data[:200]}{'...' if len(input_data)>200 else ''}")
    print("=" * 60)
    result = auto_decode(input_data)
    
    if result and 'flag' in result.lower():
        print(f"\n{'='*60}")
        print(f"FLAG FOUND: {result}")

if __name__ == '__main__':
    main()
