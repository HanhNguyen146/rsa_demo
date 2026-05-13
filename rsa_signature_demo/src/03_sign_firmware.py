#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BƯỚC 3: THÊM ĐỆM PSS VÀ KÝ CHỮ KÝ SỐ
==========================================
Script này mô phỏng toàn bộ quy trình ký số RSA-PSS.

Tại sao cần PSS Padding (Probabilistic Signature Scheme)?
─────────────────────────────────────────────────────────
  Nếu ký trực tiếp: S = hash^d mod n
    → Ký cùng file 2 lần sẽ cho CÙng chữ ký (deterministic)
    → Dễ bị tấn công thống kê (chosen-message attack)

  PSS thêm một giá trị Salt ngẫu nhiên trước khi ký:
    → Ký cùng file 2 lần cho HAI chữ ký KHÁC NHAU
    → Ngăn chặn tấn công thống kê
    → Có bằng chứng toán học về độ an toàn (provable security)

Luồng PSS (đơn giản hóa):
  mHash = SHA256(firmware)
  salt  = random bytes
  M'    = [0x00 × 8] || mHash || salt
  H     = SHA256(M')
  EM    = encode(H, salt)      ← encoded message
  S     = EM^d mod n           ← chữ ký số

Input:
  data/firmware_hash.json   — mã băm từ bước 2
  data/private_key.json     — khóa bí mật từ bước 1

Output:
  data/signature_output.json — chữ ký S và thông tin salt
"""

import hashlib
import json
import os
import sys
from pathlib import Path

PROJECT_ROOT       = Path(__file__).resolve().parent.parent
DATA_DIR           = PROJECT_ROOT / "data"
HASH_INPUT_PATH    = DATA_DIR / "firmware_hash.json"
PRIVATE_KEY_PATH   = DATA_DIR / "private_key.json"
SIGNATURE_OUT_PATH = DATA_DIR / "signature_output.json"


# ============================================================
# PHẦN 1: CHẾ ĐỘ A — MÔ PHỎNG PSS VỚI KHÓA NHỎ
# ============================================================

def pss_encode_manual(m_hash_bytes: bytes, salt: bytes, n: int) -> tuple:
    """
    Mô phỏng đơn giản hóa của PSS Encoding phù hợp với khóa nhỏ.

    Ý tưởng PSS gốc (RFC 8017 § 9.1.1):
      M'  = padding1 || mHash || salt   (padding1 = 0x00 × 8 byte)
      H   = Hash(M')                    (witness hash)
      DB  = padding2 || 0x01 || salt    (data block)
      dbMask = MGF1(H, emLen - hLen - 1)
      maskedDB = DB XOR dbMask
      EM  = maskedDB || H || 0xbc

    Phiên bản đơn giản hóa cho demo số nhỏ:
      M'  = [0x00 × 8] || mHash || salt
      H   = SHA256(M')               ← witness hash
      EM  = int(H) mod n             ← giảm về phạm vi [0, n)

    Trả về: (em_int: int, H: bytes)
    """
    # Tám byte 0x00 ở đầu là qui định của chuẩn PSS để tránh va chạm
    M_prime = (b"\x00" * 8) + m_hash_bytes + salt
    H       = hashlib.sha256(M_prime).digest()  # 32 bytes witness hash

    # Với n nhỏ (< 2^256), phải giảm EM về phạm vi [0, n)
    em_int = int.from_bytes(H, "big") % n

    return em_int, H


def sign_manual(m_hash_hex: str, private_key: dict) -> dict:
    """
    Ký số với khóa thủ công (số nguyên nhỏ).
    In chi tiết từng bước phép tính để người học quan sát.
    """
    d = private_key["d"]
    n = private_key["n"]
    m_hash_bytes = bytes.fromhex(m_hash_hex)

    sep = "-" * 56

    print(f"\n[Bước 3.2] Thông tin khóa bí mật:")
    print(f"  Chế độ       : Thủ công (số nguyên tố nhỏ)")
    print(f"  d (bí mật)   : {d}")
    print(f"  n (modulus)  : {n}  ({n.bit_length()} bit)")
    if n.bit_length() < 256:
        print(f"\n  ℹ  n chỉ có {n.bit_length()} bit < 256 bit của SHA-256.")
        print(f"     → Sẽ áp dụng: EM = int(H) mod {n} để đưa về phạm vi hợp lệ.")

    # ════════════════════════════════════════════════════════
    # LẦN KÝ THỨ NHẤT
    # ════════════════════════════════════════════════════════
    print(f"\n[Bước 3.3] {sep}")
    print(f"  LẦN KÝ THỨ NHẤT")
    print(f"  {sep}")

    salt1 = os.urandom(8)  # 8 byte ngẫu nhiên
    print(f"\n  Salt ngẫu nhiên sinh ra : {salt1.hex()}")
    print(f"  (Mỗi lần chạy, salt sẽ KHÁC nhau → chữ ký KHÁC nhau)")

    em1, H1 = pss_encode_manual(m_hash_bytes, salt1, n)

    print(f"\n  PSS Encoding chi tiết (lần 1):")
    print(f"    mHash (SHA-256 firmware)  : {m_hash_bytes.hex()[:32]}...")
    print(f"    salt1                     : {salt1.hex()}")
    print(f"    M' = [00×8] || mHash || salt1")
    print(f"    H  = SHA256(M')           : {H1.hex()}")
    print(f"    EM = int(H) mod n         : {em1}")

    print(f"\n  Tính chữ ký: S = EM^d mod n")
    print(f"    S = {em1}^{d} mod {n}")
    sig1 = pow(em1, d, n)
    print(f"    S = {sig1}")

    # ════════════════════════════════════════════════════════
    # LẦN KÝ THỨ HAI (cùng file, salt khác — minh họa PSS)
    # ════════════════════════════════════════════════════════
    print(f"\n[Bước 3.4] {sep}")
    print(f"  LẦN KÝ THỨ HAI (cùng file firmware — chứng minh PSS)")
    print(f"  {sep}")

    salt2 = os.urandom(8)
    print(f"\n  Salt ngẫu nhiên sinh ra : {salt2.hex()}")

    em2, H2 = pss_encode_manual(m_hash_bytes, salt2, n)
    print(f"  H2 = SHA256([00×8]||mHash||salt2) : {H2.hex()}")
    print(f"  EM2 = int(H2) mod n               : {em2}")

    sig2 = pow(em2, d, n)
    print(f"  S2  = EM2^d mod n                 : {sig2}")

    print(f"\n  {'─'*54}")
    print(f"  CHỨNG MINH TÍNH NGẪU NHIÊN CỦA PSS:")
    print(f"  {'─'*54}")
    print(f"  Chữ ký lần 1 : S1 = {sig1}")
    print(f"  Chữ ký lần 2 : S2 = {sig2}")
    same = sig1 == sig2
    print(f"  S1 == S2 ?    : {'CÓ ❌ (bất thường!)' if same else 'KHÔNG ✅ (đúng như mong đợi)'}")

    # Lấy kết quả lần ký thứ nhất làm output chính thức
    result = {
        "mode": "manual",
        "description": "Chữ ký số RSA-PSS (demo số nguyên tố nhỏ)",
        "algorithm": "Simplified-RSA-PSS-SHA256",
        "original_hash_hex": m_hash_hex,
        "salt_hex": salt1.hex(),
        "salt_bytes_decimal": list(salt1),
        "witness_H_hex": H1.hex(),
        "encoded_message_int": em1,
        "signature_int": sig1,
        "signature_hex": format(sig1, "x"),
        "signing_demo": {
            "note": "Ký 2 lần với 2 salt khác nhau để chứng minh PSS Randomization",
            "round1": {"salt_hex": salt1.hex(), "encoded_message": em1, "signature_int": sig1},
            "round2": {"salt_hex": salt2.hex(), "encoded_message": em2, "signature_int": sig2},
            "signatures_are_different": sig1 != sig2
        }
    }
    return result


# ============================================================
# PHẦN 2: CHẾ ĐỘ B — KÝ CHUẨN RSA-PSS VỚI KHÓA 2048-BIT
# ============================================================

def sign_standard(m_hash_hex: str, private_key: dict) -> dict:
    """
    Ký số với RSA-PSS chuẩn sử dụng thư viện cryptography.
    Đây là phương pháp đúng chuẩn RFC 8017 dùng trong thực tế.
    """
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa, padding
        from cryptography.hazmat.backends import default_backend
    except ImportError:
        print("  ❌ Chưa cài thư viện 'cryptography'. Chạy: pip install cryptography")
        sys.exit(1)

    d = private_key["d"]
    n = private_key["n"]
    p = private_key.get("p")
    q = private_key.get("q")
    e = 65537  # Giá trị chuẩn

    print(f"\n[Bước 3.2] Thông tin khóa bí mật:")
    print(f"  Chế độ    : Chuẩn RSA {n.bit_length()}-bit")
    print(f"  e         : {e}")
    print(f"  n (hex)   : {hex(n)[:18]}...{hex(n)[-10:]}")

    # Tái tạo đối tượng RSA private key từ tham số số học lưu trong JSON
    dp  = d % (p - 1)          # d mod (p-1)  — tham số CRT
    dq  = d % (q - 1)          # d mod (q-1)  — tham số CRT
    qi  = pow(q, -1, p)        # q^(-1) mod p — tham số CRT

    priv_numbers   = rsa.RSAPrivateNumbers(
        p=p, q=q, d=d, dmp1=dp, dmq1=dq, iqmp=qi,
        public_numbers=rsa.RSAPublicNumbers(e=e, n=n)
    )
    private_key_obj = priv_numbers.private_key(default_backend())

    # Đọc firmware gốc để ký (thư viện sẽ tự hash bên trong)
    firmware_path = DATA_DIR / "firmware.bin"
    if not firmware_path.exists():
        print(f"  ❌ Không tìm thấy {firmware_path}. Chạy bước 2 trước!")
        sys.exit(1)

    with open(firmware_path, "rb") as f:
        firmware_data = f.read()

    sep = "-" * 56

    # ════════════════════════════════════════════════════════
    # LẦN KÝ THỨ NHẤT
    # ════════════════════════════════════════════════════════
    print(f"\n[Bước 3.3] {sep}")
    print(f"  LẦN KÝ THỨ NHẤT (RSA-PSS chuẩn)")
    print(f"  {sep}")
    print(f"  Chuẩn đệm   : RSASSA-PSS (RFC 8017 § 8.1)")
    print(f"  Hash chính  : SHA-256")
    print(f"  MGF         : MGF1 (Mask Generation Function 1)")
    print(f"  Salt length : MAX (32 bytes = độ dài SHA-256)")

    # Thư viện tự sinh salt ngẫu nhiên bên trong mỗi lần ký
    signature1 = private_key_obj.sign(
        firmware_data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH  # salt = 32 bytes ngẫu nhiên
        ),
        hashes.SHA256()
    )

    print(f"\n  Chữ ký S1 (64 char đầu hex): {signature1.hex()[:64]}...")
    print(f"  Độ dài chữ ký: {len(signature1)} bytes = {len(signature1) * 8} bit")

    # ════════════════════════════════════════════════════════
    # LẦN KÝ THỨ HAI — minh họa tính ngẫu nhiên
    # ════════════════════════════════════════════════════════
    print(f"\n[Bước 3.4] {sep}")
    print(f"  LẦN KÝ THỨ HAI (cùng firmware, salt PSS khác)")
    print(f"  {sep}")

    signature2 = private_key_obj.sign(
        firmware_data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    print(f"  Chữ ký S2 (64 char đầu hex): {signature2.hex()[:64]}...")

    print(f"\n  {'─'*54}")
    print(f"  CHỨNG MINH TÍNH NGẪU NHIÊN CỦA PSS:")
    print(f"  {'─'*54}")
    print(f"  S1[:32 hex] : {signature1.hex()[:32]}")
    print(f"  S2[:32 hex] : {signature2.hex()[:32]}")
    same = signature1 == signature2
    print(f"  S1 == S2 ?  : {'CÓ ❌ (bất thường!)' if same else 'KHÔNG ✅ (đúng như mong đợi)'}")

    result = {
        "mode": "standard",
        "description": "Chữ ký số RSASSA-PSS chuẩn (2048-bit)",
        "algorithm": "RSASSA-PSS-SHA256",
        "mgf": "MGF1-SHA256",
        "salt_length_bytes": 32,
        "original_hash_hex": m_hash_hex,
        "salt_hex": "embedded_in_signature",
        "signature_hex": signature1.hex(),
        "signature_length_bytes": len(signature1),
        "signing_demo": {
            "note": "Ký 2 lần — salt PSS được nhúng bên trong mỗi chữ ký",
            "round1_sig_prefix_hex": signature1.hex()[:32],
            "round2_sig_prefix_hex": signature2.hex()[:32],
            "signatures_are_different": signature1 != signature2
        }
    }
    return result


# ============================================================
# PHẦN 3: HÀM CHÍNH
# ============================================================

def main():
    sep = "=" * 60
    print(f"\n{sep}")
    print("  BƯỚC 3: THÊM ĐỆM PSS VÀ KÝ SỐ")
    print(sep)

    # ── Kiểm tra file đầu vào ─────────────────────────────────
    print(f"\n[Bước 3.1] Đọc dữ liệu đầu vào:")

    if not HASH_INPUT_PATH.exists():
        print(f"  ❌ Không tìm thấy: {HASH_INPUT_PATH}")
        print("     Hãy chạy bước 2 trước: python src/02_hash_firmware.py")
        sys.exit(1)

    if not PRIVATE_KEY_PATH.exists():
        print(f"  ❌ Không tìm thấy: {PRIVATE_KEY_PATH}")
        print("     Hãy chạy bước 1 trước: python src/01_generate_keys.py")
        sys.exit(1)

    with open(HASH_INPUT_PATH, "r", encoding="utf-8") as f:
        hash_data = json.load(f)

    with open(PRIVATE_KEY_PATH, "r", encoding="utf-8") as f:
        private_key = json.load(f)

    m_hash_hex = hash_data["hash_hex"]
    mode       = private_key.get("mode", "manual")

    print(f"  ✓ Mã băm firmware : {m_hash_hex[:32]}...  ({len(m_hash_hex) * 4} bit)")
    print(f"  ✓ Chế độ khóa    : {mode}")
    print(f"  ✓ Modulus n       : {private_key['n']}  ({private_key['n'].bit_length()} bit)" if mode == "manual"
          else f"  ✓ Kích thước khóa : {private_key.get('key_size_bits', '?')} bit")

    # ── Thực hiện ký theo chế độ ─────────────────────────────
    if mode == "manual":
        result = sign_manual(m_hash_hex, private_key)
    else:
        result = sign_standard(m_hash_hex, private_key)

    # ── Lưu kết quả ──────────────────────────────────────────
    DATA_DIR.mkdir(exist_ok=True)
    with open(SIGNATURE_OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=4, ensure_ascii=False)

    print(f"\n[Lưu file]")
    print(f"  ✓ {SIGNATURE_OUT_PATH}")
    print(f"\n{sep}")
    print("  ✅  HOÀN TẤT BƯỚC 3!")
    print("  →   Bước tiếp theo: python src/04_verify_signature.py")
    print(f"{sep}\n")


if __name__ == "__main__":
    main()
