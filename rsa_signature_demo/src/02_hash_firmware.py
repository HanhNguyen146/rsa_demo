#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Buoc 2: Doc firmware.bin va tao ban bam du lieu (SHA-256).

Output:
  data/firmware_hash.json -- {"hash_hex": "..."}
"""

import hashlib
import json
from pathlib import Path

PROJECT_ROOT  = Path(__file__).resolve().parent.parent
DATA_DIR      = PROJECT_ROOT / "data"
FIRMWARE_PATH = DATA_DIR / "firmware.bin"
HASH_OUT_PATH = DATA_DIR / "firmware_hash.json"


def create_sample_firmware() -> None:
    DATA_DIR.mkdir(exist_ok=True)
    header = (
        b"FIRMWARE v1.0.0\n"
        b"================\n"
        b"Manufacturer   : DEMO Corp\n"
        b"Target Device  : IoT Sensor v2\n"
        b"Build Date     : 2025-01-01\n"
        b"Build ID       : 7f3a9c2b-1e8d-4f56-a2c3-0d1e2f3a4b5c\n"
        b"\n"
        b"[BOOT SECTION - 0x0000]\n"
    )
    binary_section = bytes(range(256)) + bytes(range(255, -1, -1)) + bytes(256)
    config_section = (
        b"\n[CONFIG SECTION - 0x0200]\n"
        b"device_id      = SENSOR_001\n"
        b"sampling_rate  = 100Hz\n"
        b"voltage        = 3.3V\n"
        b"sleep_mode     = deep\n"
        b"watchdog_timer = 30s\n"
        b"\n[END OF FIRMWARE]\n"
    )
    content = header + binary_section + config_section
    with open(FIRMWARE_PATH, "wb") as f:
        f.write(content)
    print(f"  Da tao firmware mau: {FIRMWARE_PATH.name}  ({len(content)} bytes)")


def main():
    print("Buoc 1: Doc file firmware goc.")
    if not FIRMWARE_PATH.exists():
        print(f"  Khong tim thay {FIRMWARE_PATH.name}. Dang tao file mau...")
        create_sample_firmware()

    file_size = FIRMWARE_PATH.stat().st_size
    print(f"  {FIRMWARE_PATH.name}  ({file_size} bytes)")

    with open(FIRMWARE_PATH, "rb") as f:
        firmware_data = f.read()

    print("Buoc 2: Tao ban bam du lieu.")
    hash_bytes = hashlib.sha256(firmware_data).digest()
    hash_hex   = hash_bytes.hex()
    print(f"  Ban bam (hex): {hash_hex}")
    print(f"  Ban bam (int): {int.from_bytes(hash_bytes, 'big')}")

    print("Buoc 3: Ghi ket qua bam vao file.")
    DATA_DIR.mkdir(exist_ok=True)
    with open(HASH_OUT_PATH, "w", encoding="utf-8") as f:
        json.dump({"hash_hex": hash_hex}, f, indent=4)
    print("  firmware_hash.json -> OK")
    print("Hoan tat. Chay tiep: python src/03_sign_firmware.py")


if __name__ == "__main__":
    main()
