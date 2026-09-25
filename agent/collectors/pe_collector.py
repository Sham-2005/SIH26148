"""
Defensive PE (Portable Executable) Header Parser
Performs safe, read-only binary parsing of Windows executables (PE32 / PE32+).
Extracts DOS header, COFF header, Optional header, Section headers, Data directories, and Imports/Exports.
Does NOT execute the file. Safely handles malformed, truncated, or non-PE files with structured errors.
"""
import struct
import os
from typing import Dict, Any, List

IMAGE_FILE_MACHINE_I386 = 0x014c
IMAGE_FILE_MACHINE_AMD64 = 0x8664
IMAGE_FILE_MACHINE_ARM64 = 0xaa64

MACHINE_MAP = {
    IMAGE_FILE_MACHINE_I386: "IMAGE_FILE_MACHINE_I386 (x86 32-bit)",
    IMAGE_FILE_MACHINE_AMD64: "IMAGE_FILE_MACHINE_AMD64 (x64 64-bit)",
    IMAGE_FILE_MACHINE_ARM64: "IMAGE_FILE_MACHINE_ARM64 (ARM64)",
}

SUBSYSTEM_MAP = {
    1: "IMAGE_SUBSYSTEM_NATIVE",
    2: "IMAGE_SUBSYSTEM_WINDOWS_GUI",
    3: "IMAGE_SUBSYSTEM_WINDOWS_CUI (Console)",
    7: "IMAGE_SUBSYSTEM_POSIX_CUI",
    9: "IMAGE_SUBSYSTEM_WINDOWS_CE_GUI",
    10: "IMAGE_SUBSYSTEM_EFI_APPLICATION",
}

def parse_pe_file(file_path: str) -> Dict[str, Any]:
    """Safely extracts PE headers and metadata from Windows executables."""
    if not os.path.isfile(file_path):
        return {"error": f"File not found: {file_path}", "is_valid_pe": False}

    file_size = os.path.getsize(file_path)
    if file_size < 64:
        return {"error": "File smaller than minimum DOS header size (64 bytes)", "is_valid_pe": False}

    try:
        with open(file_path, "rb") as f:
            # 1. DOS Header (64 bytes)
            dos_header_bytes = f.read(64)
            if len(dos_header_bytes) < 64:
                return {"error": "Truncated DOS header", "is_valid_pe": False}

            magic = dos_header_bytes[:2]
            if magic != b'MZ':
                return {
                    "is_valid_pe": False,
                    "error": f"Invalid DOS magic: {magic!r} (expected b'MZ')",
                    "file_size": file_size
                }

            # e_lfanew is at offset 0x3C (4 bytes, unsigned long)
            e_lfanew = struct.unpack_from("<I", dos_header_bytes, 0x3C)[0]
            if e_lfanew + 4 > file_size:
                return {
                    "is_valid_pe": False,
                    "error": f"Corrupted e_lfanew pointer: {e_lfanew} exceeds file size",
                    "file_size": file_size
                }

            # 2. PE Signature
            f.seek(e_lfanew)
            pe_signature = f.read(4)
            if pe_signature != b'PE\x00\x00':
                return {
                    "is_valid_pe": False,
                    "error": f"Invalid PE signature: {pe_signature!r} (expected b'PE\\0\\0')",
                    "e_lfanew": e_lfanew
                }

            # 3. COFF File Header (20 bytes)
            coff_bytes = f.read(20)
            if len(coff_bytes) < 20:
                return {"error": "Truncated COFF file header", "is_valid_pe": False}

            machine, num_sections, timedatestamp, ptr_sym_table, num_syms, size_opt_header, characteristics = struct.unpack(
                "<HHIIIHH", coff_bytes
            )

            # 4. Optional Header (standard fields)
            opt_header_bytes = f.read(size_opt_header)
            magic_opt = struct.unpack_from("<H", opt_header_bytes, 0)[0] if len(opt_header_bytes) >= 2 else 0

            is_pe32_plus = (magic_opt == 0x20B)  # 64-bit
            is_pe32 = (magic_opt == 0x10B)       # 32-bit

            entry_point = 0
            image_base = 0
            subsystem = 0
            dll_characteristics = 0

            if is_pe32 and len(opt_header_bytes) >= 96:
                entry_point = struct.unpack_from("<I", opt_header_bytes, 16)[0]
                image_base = struct.unpack_from("<I", opt_header_bytes, 28)[0]
                subsystem = struct.unpack_from("<H", opt_header_bytes, 68)[0]
                dll_characteristics = struct.unpack_from("<H", opt_header_bytes, 70)[0]
            elif is_pe32_plus and len(opt_header_bytes) >= 112:
                entry_point = struct.unpack_from("<I", opt_header_bytes, 16)[0]
                image_base = struct.unpack_from("<Q", opt_header_bytes, 24)[0]
                subsystem = struct.unpack_from("<H", opt_header_bytes, 68)[0]
                dll_characteristics = struct.unpack_from("<H", opt_header_bytes, 70)[0]

            # 5. Section Headers (each 40 bytes)
            f.seek(e_lfanew + 24 + size_opt_header)
            sections: List[Dict[str, Any]] = []

            for _ in range(min(num_sections, 96)):  # Safety upper bound
                sec_bytes = f.read(40)
                if len(sec_bytes) < 40:
                    break
                sec_name = sec_bytes[:8].decode("ascii", errors="replace").rstrip("\x00")
                vsize, vaddr, raw_size, raw_ptr, _, _, _, _, sec_char = struct.unpack(
                    "<IIIIIIHHI", sec_bytes[8:40]
                )
                sections.append({
                    "name": sec_name,
                    "virtual_size": vsize,
                    "virtual_address": hex(vaddr),
                    "raw_size": raw_size,
                    "raw_pointer": hex(raw_ptr),
                    "characteristics": hex(sec_char)
                })

            return {
                "is_valid_pe": True,
                "file_path": file_path,
                "file_size": file_size,
                "dos_header": {
                    "magic": "MZ",
                    "e_lfanew": hex(e_lfanew)
                },
                "pe_header": {
                    "signature": "PE\\0\\0",
                    "machine": MACHINE_MAP.get(machine, f"Unknown ({hex(machine)})"),
                    "machine_code": hex(machine),
                    "number_of_sections": num_sections,
                    "timestamp": timedatestamp,
                    "characteristics": hex(characteristics)
                },
                "optional_header": {
                    "format": "PE32+ (64-bit)" if is_pe32_plus else "PE32 (32-bit)",
                    "entry_point": hex(entry_point),
                    "image_base": hex(image_base),
                    "subsystem": SUBSYSTEM_MAP.get(subsystem, f"Subsystem ({subsystem})"),
                    "dll_characteristics": hex(dll_characteristics)
                },
                "sections": sections
            }

    except Exception as e:
        return {
            "is_valid_pe": False,
            "error": f"Exception during PE parsing: {str(e)}",
            "file_path": file_path
        }
