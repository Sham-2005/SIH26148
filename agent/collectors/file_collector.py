"""
File & Filesystem Forensic Collector
Computes cryptographic hashes, Shannon entropy, extracted strings, and file metadata.
"""
import os
import math
import hashlib
import string
from typing import Dict, Any, List, Optional

def calculate_file_entropy(file_path: str) -> float:
    """Calculates Shannon entropy of file contents (range 0.0 to 8.0)."""
    if not os.path.isfile(file_path):
        return 0.0

    byte_counts = [0] * 256
    total_bytes = 0

    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            total_bytes += len(chunk)
            for b in chunk:
                byte_counts[b] += 1

    if total_bytes == 0:
        return 0.0

    entropy = 0.0
    for count in byte_counts:
        if count > 0:
            p = count / total_bytes
            entropy -= p * math.log2(p)
    return round(entropy, 4)

def collect_file_hash(file_path: str) -> Dict[str, Any]:
    """Calculates MD5, SHA-1, and SHA-256 of target file."""
    if not os.path.isfile(file_path):
        return {"error": f"File not found: {file_path}"}

    md5_hash = hashlib.md5()
    sha1_hash = hashlib.sha1()
    sha256_hash = hashlib.sha256()

    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            md5_hash.update(chunk)
            sha1_hash.update(chunk)
            sha256_hash.update(chunk)

    return {
        "path": file_path,
        "md5": md5_hash.hexdigest(),
        "sha1": sha1_hash.hexdigest(),
        "sha256": sha256_hash.hexdigest(),
        "size_bytes": os.path.getsize(file_path)
    }

def collect_file_metadata(file_path: str) -> Dict[str, Any]:
    if not os.path.exists(file_path):
        return {"error": f"Path not found: {file_path}"}

    stat = os.stat(file_path)
    return {
        "path": file_path,
        "is_file": os.path.isfile(file_path),
        "is_dir": os.path.isdir(file_path),
        "size_bytes": stat.st_size,
        "created_at": stat.st_ctime,
        "modified_at": stat.st_mtime,
        "accessed_at": stat.st_atime,
        "permissions_octal": oct(stat.st_mode)
    }

def collect_file_strings(file_path: str, min_length: int = 4, max_strings: int = 200) -> List[str]:
    """Extracts printable ASCII strings from file."""
    if not os.path.isfile(file_path):
        return []

    printable = set(bytes(string.printable, 'ascii'))
    extracted = []
    current = []

    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            for byte in chunk:
                if byte in printable and byte not in (b'\r'[0], b'\n'[0], b'\t'[0]):
                    current.append(chr(byte))
                else:
                    if len(current) >= min_length:
                        extracted.append("".join(current))
                        if len(extracted) >= max_strings:
                            return extracted
                    current.clear()

    if len(current) >= min_length and len(extracted) < max_strings:
        extracted.append("".join(current))

    return extracted

def collect_filesystem_scan(target_dir: str, max_entries: int = 100) -> List[Dict[str, Any]]:
    if not os.path.isdir(target_dir):
        return [{"error": f"Directory not found: {target_dir}"}]

    entries = []
    for root, dirs, files in os.walk(target_dir):
        for f in files:
            full_p = os.path.join(root, f)
            try:
                entries.append({
                    "name": f,
                    "path": full_p,
                    "size_bytes": os.path.getsize(full_p)
                })
            except Exception:
                continue
            if len(entries) >= max_entries:
                return entries
    return entries
