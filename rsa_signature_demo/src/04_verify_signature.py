#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BƯỚC 4: XÁC THỰC CHỮ KÝ SỐ
==============================
Script này mô phỏng phía THIẾT BỊ NHẬN khi kiểm tra firmware:

Quy trình xác thực RSA-PSS (phía nhận):
  1. Đọc firmware nhận được và tính lại hash
  2. Dùng Public Key để "mở khóa" chữ ký → thu về EM_actual
  3. Dùng hash + salt đã đính kèm để tính lại EM_expected
  4. So sánh: EM_actual == EM_expected ?
       CÓ  → ✅ Firmware hợp lệ, chính hãng, không bị chỉnh sửa
       KHÔNG → ❌ Firmware bị giả mạo hoặc hỏng, từ chối!

Lý do dùng Public Key để xác thực:
  • Ai cũng có Public Key → ai cũng có thể XÁC THỰC
  • Chỉ người giữ Private Key mới có thể KÝ
  • Đây chính là bất đối xứng cốt lõi của RSA

Input:
  data/firmware.bin          — firmware cần kiểm tra
  data/public_key.json       — khóa công khai của NSX
  data/signature_output.json — chữ ký đính kèm firmware

Output:
  In kết quả "✅ HỢP LỆ" hoặc "❌ BỊ GIẢ MẠO" ra màn hình
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


# ============================================================
# PHẦN 1: CHẾ ĐỘ A — XÁC THỰC VỚI KHÓA NHỎ (MANUAL MODE)
# ============================================================

def verify_manual(firmware_data: bytes, public_key: dict, sig_data: dict) -> bool:
    """
    Xác thực chữ ký sử dụng khóa thủ công (số nguyên nhỏ).
    Từng bước được in ra để người học quan sát quy trình.
    """
    e       = public_key["e"]
    n       = public_key["n"]
    sig_int = int(sig_data["signature_hex"], 16)
    salt    = bytes.fromhex(sig_data["salt_hex"])

    print(f"\n[Bước 4.2] Thông tin khóa công khai:")
    print(f"  Chế độ    : Thủ công (số nguyên tố nhỏ)")
    print(f"  e         : {e}")
    print(f"  n         : {n}  ({n.bit_length()} bit)")

    # ── Bước A: Tính lại hash firmware nhận được ─────────────
    print(f"\n[Bước 4.3] Tính lại SHA-256 của firmware nhận được:")
    m_hash_bytes     = hashlib.sha256(firmware_data).digest()
    m_hash_hex_recalc = m_hash_bytes.hex()
    m_hash_hex_orig   = sig_data["original_hash_hex"]

    print(f"  Hash tính lại (firmware hiện tại) : {m_hash_hex_recalc}")
    print(f"  Hash lưu trong chữ ký (gốc)       : {m_hash_hex_orig}")
    hash_match = m_hash_hex_recalc == m_hash_hex_orig
    print(f"  Hai hash khớp nhau? : {'CÓ ✅' if hash_match else 'KHÔNG ❌ (firmware đã bị sửa!)'}")

    # ── Bước B: Giải mã chữ ký bằng Public Key ───────────────
    print(f"\n[Bước 4.4] Giải mã chữ ký bằng Public Key (e, n):")
    print(f"  EM_actual = S^e mod n")
    print(f"            = {sig_int}^{e} mod {n}")
    em_actual = pow(sig_int, e, n)
    print(f"            = {em_actual}")

    # ── Bước C: Tái tạo EM từ hash + salt đính kèm ───────────
    print(f"\n[Bước 4.5] Tái tạo EM_expected từ hash mới tính + salt đính kèm:")
    print(f"  Salt đọc từ signature_output.json : {salt.hex()}")
    M_prime      = (b"\x00" * 8) + m_hash_bytes + salt
    H_recalc     = hashlib.sha256(M_prime).digest()
    em_expected  = int.from_bytes(H_recalc, "big") % n
    print(f"  M' = [00×8] || mHash_mới || salt")
    print(f"  H  = SHA256(M')   : {H_recalc.hex()}")
    print(f"  EM_expected = int(H) mod n = {em_expected}")

    # ── Bước D: So sánh kết luận ──────────────────────────────
    print(f"\n[Bước 4.6] So sánh kết quả cuối:")
    print(f"  EM từ chữ ký  (EM_actual)   : {em_actual}")
    print(f"  EM tính lại   (EM_expected) : {em_expected}")
    is_valid = em_actual == em_expected
    print(f"  Kết luận: EM_actual == EM_expected ? → "
          f"{'CÓ ✅' if is_valid else 'KHÔNG ❌'}")
    return is_valid


# ============================================================
# PHẦN 2: CHẾ ĐỘ B — XÁC THỰC CHUẨN RSA-PSS
# ============================================================

def verify_standard(firmware_data: bytes, public_key: dict, sig_data: dict) -> bool:
    """
    Xác thực chữ ký RSA-PSS chuẩn bằng thư viện cryptography.
    """
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa, padding
        from cryptography.hazmat.backends import default_backend
        from cryptography.exceptions import InvalidSignature
    except ImportError:
        print("  ❌ Chưa cài thư viện 'cryptography'. Chạy: pip install cryptography")
        sys.exit(1)

    e               = public_key["e"]
    n               = public_key["n"]
    signature_bytes = bytes.fromhex(sig_data["signature_hex"])

    print(f"\n[Bước 4.2] Thông tin khóa công khai:")
    print(f"  Chế độ    : Chuẩn RSA {n.bit_length()}-bit")
    print(f"  e         : {e}")
    print(f"  n (hex)   : {hex(n)[:18]}...{hex(n)[-10:]}")

    # Tái tạo đối tượng RSA public key từ tham số (e, n)
    pub_numbers    = rsa.RSAPublicNumbers(e=e, n=n)
    public_key_obj = pub_numbers.public_key(default_backend())

    # ── Tính lại hash để hiển thị so sánh ────────────────────
    print(f"\n[Bước 4.3] Tính lại SHA-256 của firmware nhận được:")
    m_hash_recalc = hashlib.sha256(firmware_data).hexdigest()
    m_hash_orig   = sig_data["original_hash_hex"]
    print(f"  Hash tính lại : {m_hash_recalc}")
    print(f"  Hash gốc      : {m_hash_orig}")

    # ── Thực hiện xác thực PSS ────────────────────────────────
    print(f"\n[Bước 4.4] Thực hiện xác thực RSASSA-PSS:")
    print(f"  Chuẩn    : RFC 8017 § 8.1.2 (RSASSA-PSS-VERIFY)")
    print(f"  Hash     : SHA-256")
    print(f"  MGF      : MGF1-SHA256")
    print(f"  Salt len : AUTO (thư viện tự đọc từ chữ ký)")
    print(f"  Thao tác : public_key.verify(signature, firmware, PSS, SHA256)")

    try:
        public_key_obj.verify(
            signature_bytes,
            firmware_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.AUTO  # Tự nhận diện salt length từ chữ ký
            ),
            hashes.SHA256()
        )
        print(f"  Kết quả : Không ném ngoại lệ → Chữ ký hợp lệ ✅")
        return True
    except InvalidSignature:
        print(f"  Kết quả : InvalidSignature exception → Chữ ký KHÔNG hợp lệ ❌")
        return False


# ============================================================
# PHẦN 3: DEMO PHÁT HIỆN GIẢ MẠO — MỤC ĐÍCH GIẢNG DẠY
# ============================================================

def demo_tamper_detection(firmware_data: bytes, public_key: dict,
                          sig_data: dict, mode: str) -> None:
    """
    Giả mạo firmware (thay đổi 1 byte) và chứng minh
    hệ thống sẽ phát hiện ra ngay lập tức.
    """
    sep = "-" * 56
    print(f"\n{sep}")
    print("  [DEMO] Mô phỏng kịch bản tấn công: Giả mạo firmware")
    print(sep)

    # Kẻ tấn công thay đổi 1 byte cuối cùng của firmware
    original_last_byte = firmware_data[-1]
    tampered_last_byte = firmware_data[-1] ^ 0xFF  # Lật toàn bộ 8 bit
    tampered_data      = firmware_data[:-1] + bytes([tampered_last_byte])

    print(f"\n  Hành động tấn công:")
    print(f"    Byte vị trí cuối (byte #{len(firmware_data) - 1})")
    print(f"    Giá trị gốc     : 0x{original_last_byte:02X} ({original_last_byte})")
    print(f"    Giá trị bị sửa  : 0x{tampered_last_byte:02X} ({tampered_last_byte})")
    print(f"    (Kẻ tấn công đã sửa firmware và gửi đến thiết bị)")

    print(f"\n  → Thiết bị đang xác thực firmware BỊ SỬA...")

    if mode == "manual":
        tampered_valid = verify_manual(tampered_data, public_key, sig_data)
    else:
        tampered_valid = verify_standard(tampered_data, public_key, sig_data)

    print(f"\n  Kết quả xác thực firmware bị giả mạo:")
    if not tampered_valid:
        print(f"  ✅ HỆ THỐNG ĐÃ PHÁT HIỆN GIẢ MẠO THÀNH CÔNG!")
        print(f"     Firmware bị sửa → Hash thay đổi → Chữ ký sai → Từ chối!")
    else:
        print(f"  ❌ CẢNH BÁO: Hệ thống không phát hiện được — kiểm tra lại!")


# ============================================================
# PHẦN 4: HÀM CHÍNH
# ============================================================

def main():
    sep = "=" * 60
    print(f"\n{sep}")
    print("  BƯỚC 4: XÁC THỰC CHỮ KÝ SỐ RSA-PSS")
    print(sep)

    # ── Kiểm tra và đọc tất cả file đầu vào ──────────────────
    print(f"\n[Bước 4.1] Kiểm tra và đọc dữ liệu đầu vào:")

    required_files = [
        (FIRMWARE_PATH,   "firmware.bin          — firmware cần xác thực"),
        (PUBLIC_KEY_PATH, "public_key.json       — khóa công khai NSX"),
        (SIGNATURE_PATH,  "signature_output.json — chữ ký đính kèm firmware"),
    ]

    for path, desc in required_files:
        if not path.exists():
            print(f"  ❌ Không tìm thấy: {path.name}")
            print(f"     Mô tả: {desc}")
            print(f"     → Hãy chạy lần lượt các bước 1, 2, 3 trước!")
            sys.exit(1)
        print(f"  ✓ {path.name:<30} {desc}")

    with open(FIRMWARE_PATH, "rb") as f:
        firmware_data = f.read()

    with open(PUBLIC_KEY_PATH, "r", encoding="utf-8") as f:
        public_key = json.load(f)

    with open(SIGNATURE_PATH, "r", encoding="utf-8") as f:
        sig_data = json.load(f)

    mode = sig_data.get("mode", "manual")
    print(f"\n  Kích thước firmware : {len(firmware_data)} bytes")
    print(f"  Chế độ xác thực    : {mode}")
    print(f"  Thuật toán chữ ký  : {sig_data.get('algorithm', 'N/A')}")

    # ── Thực hiện xác thực ────────────────────────────────────
    print(f"\n{'='*60}")
    print(f"  TIẾN HÀNH XÁC THỰC...")
    print(f"{'='*60}")

    if mode == "manual":
        is_valid = verify_manual(firmware_data, public_key, sig_data)
    else:
        is_valid = verify_standard(firmware_data, public_key, sig_data)

    # ── Hiển thị kết quả cuối ─────────────────────────────────
    print(f"\n{'='*60}")
    if is_valid:
        print(f"  ✅  KẾT QUẢ: CHỮ KÝ HỢP LỆ — FIRMWARE AN TOÀN")
        print(f"  {'─'*56}")
        print(f"  Firmware này đã được xác nhận:")
        print(f"    • Tính xác thực : đến từ đúng nhà sản xuất (NSX)")
        print(f"    • Tính toàn vẹn : nội dung KHÔNG bị chỉnh sửa")
        print(f"    → An toàn để cài đặt lên thiết bị.")
    else:
        print(f"  ❌  KẾT QUẢ: CHỮ KÝ KHÔNG HỢP LỆ — TỪ CHỐI FIRMWARE!")
        print(f"  {'─'*56}")
        print(f"  Firmware bị từ chối vì có thể:")
        print(f"    • Đến từ nguồn không xác thực (giả mạo NSX)")
        print(f"    • Bị chỉnh sửa sau khi NSX đã ký")
        print(f"    → KHÔNG cài đặt — nguy hiểm cho thiết bị!")
    print(f"{'='*60}")

    # ── Hỏi người dùng có muốn chạy demo giả mạo không ──────
    print()
    run_demo = input("  Xem demo phát hiện giả mạo firmware? (y/n) [mặc định: y]: ")
    if run_demo.strip().lower() != "n":
        demo_tamper_detection(firmware_data, public_key, sig_data, mode)

    print(f"\n{sep}")
    print("  ✅  HOÀN TẤT TOÀN BỘ QUY TRÌNH KÝ SỐ RSA-PSS!")
    print(f"{sep}\n")


if __name__ == "__main__":
    main()
