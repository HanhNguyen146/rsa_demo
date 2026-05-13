#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BƯỚC 2: BĂM (HASH) FILE FIRMWARE
==================================
Script này đọc file firmware.bin và áp dụng hàm băm SHA-256.

Mục đích của bước Hashing:
  • Tạo ra "dấu vân tay số" (digital fingerprint) cố định 256 bit
    đại diện cho toàn bộ nội dung firmware, dù firmware lớn bao nhiêu.
  • RSA chỉ hoạt động trên số nguyên nhỏ hơn n → không thể ký
    trực tiếp file lớn → phải ký trên hash thay thế.
  • Bất kỳ thay đổi nào dù nhỏ nhất trên firmware
    đều tạo ra hash hoàn toàn khác (Avalanche Effect).

Input:
  data/firmware.bin  — file firmware cần bảo vệ

Output:
  data/firmware_hash.json — chuỗi hex của SHA-256 hash
"""

import hashlib
import json
from pathlib import Path

PROJECT_ROOT   = Path(__file__).resolve().parent.parent
DATA_DIR       = PROJECT_ROOT / "data"
FIRMWARE_PATH  = DATA_DIR / "firmware.bin"
HASH_OUT_PATH  = DATA_DIR / "firmware_hash.json"


# ============================================================
# PHẦN 1: TẠO FILE FIRMWARE MẪU
# ============================================================

def create_sample_firmware() -> None:
    """
    Tạo một file firmware mẫu để demo nếu chưa có file thật.
    Nội dung giả lập header metadata + dữ liệu nhị phân mẫu.
    """
    DATA_DIR.mkdir(exist_ok=True)

    # Header dạng text
    header = (
        b"FIRMWARE v1.0.0\n"
        b"================\n"
        b"Manufacturer   : DEMO Corp\n"
        b"Target Device  : IoT Sensor v2\n"
        b"Build Date     : 2025-01-01\n"
        b"Build ID       : 7f3a9c2b-1e8d-4f56-a2c3-0d1e2f3a4b5c\n"
        b"Encryption     : None (demo)\n"
        b"Signature Algo : RSA-PSS-SHA256\n"
        b"\n"
        b"[BOOT SECTION - 0x0000]\n"
    )

    # Giả lập dữ liệu nhị phân của firmware (256 byte đặc trưng + 512 byte mẫu)
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

    print(f"  ✓ Đã tạo firmware mẫu: {FIRMWARE_PATH}  ({len(content)} bytes)")


# ============================================================
# PHẦN 2: TÍNH HASH SHA-256
# ============================================================

def compute_sha256(file_path: Path) -> tuple:
    """
    Tính SHA-256 hash của file bằng cách đọc từng chunk.
    Hỗ trợ file lớn tùy ý mà không cần nạp toàn bộ vào RAM.

    Trả về: (hash_bytes: bytes, hash_hex: str, total_bytes: int)
    """
    hasher     = hashlib.sha256()
    total_read = 0
    CHUNK_SIZE = 65536  # 64 KB mỗi lần đọc

    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            hasher.update(chunk)
            total_read += len(chunk)

    return hasher.digest(), hasher.hexdigest(), total_read


# ============================================================
# PHẦN 3: HIỂN THỊ TRỰC QUAN
# ============================================================

def show_bits(hash_hex: str, n_bytes: int = 4) -> str:
    """
    Hiển thị n_bytes byte đầu của hash dưới dạng bit nhị phân.
    Mỗi nhóm 8 bit cách nhau bởi dấu cách để dễ đọc.
    """
    raw = bytes.fromhex(hash_hex[:n_bytes * 2])
    bits = "".join(format(b, "08b") for b in raw)
    return " ".join(bits[i:i+8] for i in range(0, len(bits), 8))


def show_avalanche_effect(original_bytes: bytes, original_hash_hex: str) -> None:
    """
    Minh họa Hiệu ứng tuyết lở (Avalanche Effect):
    Thay đổi 1 bit bất kỳ → hash thay đổi ~50% số bit.
    """
    # Lật bit cuối cùng của byte cuối (XOR với 1)
    tampered = bytearray(original_bytes)
    tampered[-1] ^= 0x01  # Đổi bit thấp nhất của byte cuối
    tampered_hash = hashlib.sha256(bytes(tampered)).hexdigest()

    orig_int    = int(original_hash_hex, 16)
    tamper_int  = int(tampered_hash, 16)
    diff_bits   = bin(orig_int ^ tamper_int).count("1")

    print(f"\n[Bước 2.4] Minh họa Avalanche Effect (Hiệu ứng tuyết lở):")
    print(f"  Thay đổi: lật 1 bit cuối của firmware (byte {len(original_bytes) - 1})")
    print(f"  Hash gốc     : {original_hash_hex[:32]}...")
    print(f"  Hash sửa 1bit: {tampered_hash[:32]}...")
    print(f"  Số bit thay đổi: {diff_bits} / 256 bit ({diff_bits / 256 * 100:.1f}%)")
    print(f"  → Thay đổi nhỏ nhất cũng làm hash thay đổi hoàn toàn!")


# ============================================================
# PHẦN 4: HÀM CHÍNH
# ============================================================

def main():
    sep = "=" * 60
    print(f"\n{sep}")
    print("  BƯỚC 2: BĂM FILE FIRMWARE (SHA-256)")
    print(sep)

    # ── Kiểm tra và tạo firmware nếu chưa có ─────────────────
    if not FIRMWARE_PATH.exists():
        print(f"\n  ℹ  Không tìm thấy {FIRMWARE_PATH.name}")
        print("     Đang tạo file firmware mẫu để demo...")
        create_sample_firmware()

    # ── Bước 2.1: Thông tin file đầu vào ─────────────────────
    file_size = FIRMWARE_PATH.stat().st_size
    print(f"\n[Bước 2.1] Đọc file firmware đầu vào:")
    print(f"  Đường dẫn : {FIRMWARE_PATH}")
    print(f"  Kích thước : {file_size} bytes  ({file_size / 1024:.2f} KB)")

    with open(FIRMWARE_PATH, "rb") as f:
        firmware_data = f.read()

    # Hiển thị 32 byte đầu để người học thấy nội dung thô
    first_32 = firmware_data[:32]
    print(f"  32 byte đầu (hex)  : {first_32.hex()}")
    print(f"  32 byte đầu (text) : {repr(first_32)}")

    # ── Bước 2.2: Giải thích thuật toán SHA-256 ──────────────
    print(f"\n[Bước 2.2] Thuật toán băm được sử dụng: SHA-256")
    print(f"  Họ thuật toán : SHA-2  (Secure Hash Algorithm 2)")
    print(f"  Kích thước đầu ra: 256 bit = 32 bytes = 64 ký tự hex")
    print(f"  Tính chất cốt lõi:")
    print(f"    • Một chiều     : Không thể tìm ngược firmware từ hash")
    print(f"    • Chống va chạm : Cực kỳ khó tìm 2 file cùng hash")
    print(f"    • Tất định      : Cùng file → luôn cùng hash")
    print(f"  Chuẩn áp dụng : FIPS PUB 180-4, RFC 6234")

    # ── Bước 2.3: Thực hiện băm ──────────────────────────────
    print(f"\n[Bước 2.3] Thực hiện băm SHA-256:")
    print(f"  Đang đọc và băm file theo từng chunk 64 KB...")

    hash_bytes, hash_hex, total_read = compute_sha256(FIRMWARE_PATH)

    print(f"  Đã xử lý  : {total_read} bytes")
    print(f"  SHA-256 (hex)    : {hash_hex}")
    print(f"  SHA-256 (32 byte): {list(hash_bytes)}")
    print(f"  Độ dài chuỗi hex : {len(hash_hex)} ký tự")

    print(f"\n  Biểu diễn nhị phân (32 bit đầu):")
    print(f"  {show_bits(hash_hex, 4)}")

    # ── Bước 2.4: Minh họa Avalanche Effect ──────────────────
    show_avalanche_effect(firmware_data, hash_hex)

    # ── Lưu kết quả ra JSON ───────────────────────────────────
    result = {
        "description": "Kết quả băm SHA-256 của file firmware",
        "input_file": FIRMWARE_PATH.name,
        "input_file_size_bytes": file_size,
        "hash_algorithm": "SHA-256",
        "hash_output_bits": 256,
        "hash_output_bytes": 32,
        "hash_hex": hash_hex,
        "hash_bytes_decimal": list(hash_bytes)
    }

    DATA_DIR.mkdir(exist_ok=True)
    with open(HASH_OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=4, ensure_ascii=False)

    print(f"\n[Lưu file]")
    print(f"  ✓ {HASH_OUT_PATH}")
    print(f"\n{sep}")
    print("  ✅  HOÀN TẤT BƯỚC 2!")
    print("  →   Bước tiếp theo: python src/03_sign_firmware.py")
    print(f"{sep}\n")


if __name__ == "__main__":
    main()
