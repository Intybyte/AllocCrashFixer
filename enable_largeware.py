import struct
import sys
import os

def patch_largeaddressaware(exe_path):
    with open(exe_path, 'r+b') as f:
        # 1. read e_lfanew at offset 0x3C (4 bytes)
        f.seek(0x3C)
        e_lfanew_bytes = f.read(4)
        e_lfanew = struct.unpack('<I', e_lfanew_bytes)[0]

        # 2. go to characteristics, skil file descriptor (e_lfanew + 4 + 18)
        characteristics_offset = e_lfanew + 4 + 18
        f.seek(characteristics_offset)
        characteristics_bytes = f.read(2)
        characteristics = struct.unpack('<H', characteristics_bytes)[0]

        print(f"[=] Offset PE header: 0x{e_lfanew:X}")
        print(f"[=] Characteristics: 0x{characteristics:04X}")

        # 3. add LARGE_ADDRESS_AWARE flag (bit 0x20)
        if characteristics & 0x20:
            print("[!] LARGEADDRESSAWARE already enabled.")
        else:
            characteristics |= 0x20
            f.seek(characteristics_offset)
            f.write(struct.pack('<H', characteristics))
            print(f"[+] Flag LARGEADDRESSAWARE enabled: 0x{characteristics:04X}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Use: python enable_largeware.py path/to/file.exe")
        sys.exit(1)

    exe_file = sys.argv[1]

    if not os.path.isfile(exe_file):
        print(f"File non trovato: {exe_file}")
        sys.exit(1)

    patch_largeaddressaware(exe_file)
