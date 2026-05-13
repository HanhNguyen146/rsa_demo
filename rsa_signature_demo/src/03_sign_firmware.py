#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Buoc 3: Ky so thuan tuy: S = H^d mod n.

  H = int(hash(firmware)) mod n
  S = H^d mod n

Input:
  data/firmware_hash.json  -- {"hash_hex": "..."}
  data/private_key.json    -- {"d": ..., "n": ...}

Output:
  data/signature_output.json -- {"hash_int": ..., "signature_int": ..., "signature_hex": "..."}
"""

import json
import sys
from pathlib import Path

PROJECT_ROOT       = Path(__file__).resolve().parent.parent
DATA_DIR           = PROJECT_ROOT / "data"
HASH_INPUT_PATH    = DATA_DIR / "firmware_hash.json"
PRIVATE_KEY_PATH   = DATA_DIR / "private_key.json"
SIGNATURE_OUT_PATH = DATA_DIR / "signature_output.json"


def main():
    print("Buoc 1: Doc ban bam va khoa bi mat.")
    if not HASH_INPUT_PATH.exists():
        print("  Loi: Khong tim thay firmware_hash.json. Chay buoc 2 truoc.")
        sys.exit(1)
    if not PRIVATE_KEY_PATH.exists():
        print("  Loi: Khong tim thay private_key.json. Chay buoc 1 truoc.")
        sys.exit(1)

    with open(HASH_INPUT_PATH, "r", encoding="utf-8") as f:
        hash_data = json.load(f)
    with open(PRIVATE_KEY_PATH, "r", encoding="utf-8") as f:
        private_key = json.load(f)

    hash_hex = hash_data["hash_hex"]
    d = private_key["d"]
    n = private_key["n"]
    print(f"  Ban bam (hex): {hash_hex}")
    print(f"  d = {d},  n = {n}")

    print("Buoc 2: Tinh gia tri H tu ban bam.")
    H = int(hash_hex, 16) % n
    print(f"  H = int(ban_bam) mod {n} = {H}")

    print("Buoc 3: Ky: S = H^d mod n.")
    S = pow(H, d, n)
    print(f"  S = {H}^{d} mod {n} = {S}")

    print("Buoc 4: Luu chu ky vao file.")
    result = {
        "hash_int":      H,
        "signature_int": S,
        "signature_hex": format(S, "x")
    }
    DATA_DIR.mkdir(exist_ok=True)
    with open(SIGNATURE_OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=4)
    print("  signature_output.json -> OK")
    print("Hoan tat. Chay tiep: python src/04_verify_signature.py")


if __name__ == "__main__":
    main()
