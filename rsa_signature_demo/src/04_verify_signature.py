#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Buoc 4: Xac thuc chu ky thuan tuy: H' = S^e mod n.

  H_new = int(hash(firmware_nhan_duoc)) mod n
  H'    = S^e mod n
  Hop le neu H' == H_new

Input:
  data/firmware.bin          -- firmware can kiem tra
  data/public_key.json       -- {"e": ..., "n": ...}
  data/signature_output.json -- {"signature_int": ...}

Output:
  In ra "Chu ky hop le." hoac "Chu ky khong hop le."
"""

import hashlib
import json
import sys
from pathlib import Path

PROJECT_ROOT    = Path(__file__).resolve().parent.parent
DATA_DIR        = PROJECT_ROOT / "data"
FIRMWARE_PATH   = DATA_DIR / "firmware.bin"
PUBLIC_KEY_PATH = DATA_DIR / "public_key.json"
SIGNATURE_PATH  = DATA_DIR / "signature_output.json"


def compute_H(firmware_data: bytes, n: int) -> tuple:
    """Tinh H = int(hash(firmware)) mod n. Tra ve (H, hash_hex)."""
    hash_bytes = hashlib.sha256(firmware_data).digest()
    hash_hex   = hash_bytes.hex()
    H          = int(hash_hex, 16) % n
    return H, hash_hex


def verify(firmware_data: bytes, e: int, n: int, S: int) -> bool:
    H_new, hash_hex_new = compute_H(firmware_data, n)
    H_prime = pow(S, e, n)

    print(f"  Ban bam (hex): {hash_hex_new}")
    print(f"  H     = int(ban_bam) mod {n} = {H_new}")
    print(f"  H'    = {S}^{e} mod {n} = {H_prime}")

    return H_prime == H_new


def main():
    print("Buoc 1: Doc cac file dau vao.")
    for path in [FIRMWARE_PATH, PUBLIC_KEY_PATH, SIGNATURE_PATH]:
        if not path.exists():
            print(f"  Loi: Khong tim thay {path.name}.")
            sys.exit(1)

    with open(FIRMWARE_PATH, "rb") as f:
        firmware_data = f.read()
    with open(PUBLIC_KEY_PATH, "r", encoding="utf-8") as f:
        public_key = json.load(f)
    with open(SIGNATURE_PATH, "r", encoding="utf-8") as f:
        sig_data = json.load(f)

    e = public_key["e"]
    n = public_key["n"]
    S = sig_data["signature_int"]
    print(f"  firmware.bin  ({len(firmware_data)} bytes)")
    print(f"  e = {e},  n = {n}")
    print(f"  S = {S}")

    print("Buoc 2: Tinh lai ban bam, giai ma chu ky va so sanh.")
    is_valid = verify(firmware_data, e, n, S)

    if is_valid:
        print(f"  H' == H  ->  khop nhau")
        print("Chu ky hop le.")
    else:
        print(f"  H' != H  ->  khong khop")
        print("Chu ky khong hop le.")

    print()
    print("Demo: Kiem tra firmware bi sua doi.")
    tampered = firmware_data[:-1] + bytes([firmware_data[-1] ^ 0xFF])
    is_tampered_valid = verify(tampered, e, n, S)
    if not is_tampered_valid:
        print("Phat hien gia mao thanh cong.")
    else:
        print("Canh bao: Khong phat hien gia mao.")


if __name__ == "__main__":
    main()
