#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BƯỚC 1: TẠO CẶP KHÓA RSA (PUBLIC KEY & PRIVATE KEY)
=====================================================
Script này minh họa hai cách tạo cặp khóa RSA:

  (A) Nhập thủ công hai số nguyên tố p, q
      → Dùng số nhỏ để quan sát rõ từng bước tính toán
      → Không an toàn cho thực tế, chỉ dùng để học

  (B) Tự động sinh khóa RSA chuẩn 2048-bit
      → Dùng thư viện cryptography, an toàn cho thực tế

Output:
  data/public_key.json   — khóa công khai (e, n)
  data/private_key.json  — khóa bí mật (d, n)
"""

import json
import math
import sys
from pathlib import Path

# Thư mục gốc của dự án (cha của thư mục src/)
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"


# ============================================================
# PHẦN 1: CÁC HÀM TOÁN HỌC CƠ BẢN
# ============================================================

def is_prime(n: int) -> bool:
    """
    Kiểm tra n có phải số nguyên tố không.
    Dùng thử chia từ 2 đến căn bậc hai của n.
    """
    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    # Chỉ cần thử đến sqrt(n), vì nếu n = a*b thì min(a,b) <= sqrt(n)
    for i in range(3, int(math.isqrt(n)) + 1, 2):
        if n % i == 0:
            return False
    return True


def extended_gcd(a: int, b: int):
    """
    Thuật toán Euclid mở rộng.
    Tìm (g, x, y) thỏa: a*x + b*y = g = gcd(a, b).
    Đây là nền tảng để tính nghịch đảo modular.
    """
    if a == 0:
        return b, 0, 1
    g, x, y = extended_gcd(b % a, a)
    return g, y - (b // a) * x, x


def gcd(a: int, b: int) -> int:
    """Tính ước chung lớn nhất (Greatest Common Divisor)."""
    while b:
        a, b = b, a % b
    return a


def mod_inverse(e: int, phi_n: int) -> int:
    """
    Tính nghịch đảo modular: tìm d sao cho (e * d) % phi_n == 1.
    Đây chính là cách tạo ra khóa bí mật d từ e và phi(n).
    Ném ValueError nếu không tồn tại nghịch đảo.
    """
    g, x, _ = extended_gcd(e % phi_n, phi_n)
    if g != 1:
        raise ValueError(
            f"Nghịch đảo modular không tồn tại! gcd({e}, {phi_n}) = {g} ≠ 1"
        )
    return x % phi_n


def find_valid_e(phi_n: int) -> int:
    """
    Chọn số mũ công khai e hợp lệ:
      - 1 < e < phi_n
      - gcd(e, phi_n) = 1  (e và phi_n nguyên tố cùng nhau)
    Ưu tiên e = 65537 (giá trị Fermat F4, an toàn và hiệu quả).
    """
    for candidate in [65537, 257, 17, 5, 3]:
        if candidate < phi_n and gcd(candidate, phi_n) == 1:
            return candidate
    # Tìm kiếm tuần tự nếu các ứng cử viên trên không phù hợp
    for e in range(2, phi_n):
        if gcd(e, phi_n) == 1:
            return e
    raise ValueError("Không tìm được giá trị e hợp lệ!")


# ============================================================
# PHẦN 2: CHẾ ĐỘ A — TẠO KHÓA THỦ CÔNG (SỐ NHỎ)
# ============================================================

def generate_keys_manual(p: int, q: int):
    """
    Tạo cặp khóa RSA thủ công từ hai số nguyên tố p và q.
    In chi tiết từng bước để người học quan sát phép tính.
    """
    sep = "=" * 60
    print(f"\n{sep}")
    print("  CHẾ ĐỘ A — MINH HỌA THUẬT TOÁN RSA THỦ CÔNG")
    print(sep)

    # ── Bước 1.1: Kiểm tra tính nguyên tố ──────────────────
    print("\n[Bước 1.1] Kiểm tra tính nguyên tố của p và q:")
    if not is_prime(p):
        raise ValueError(f"  p = {p} KHÔNG phải số nguyên tố!")
    if not is_prime(q):
        raise ValueError(f"  q = {q} KHÔNG phải số nguyên tố!")
    if p == q:
        raise ValueError("  p và q phải KHÁC nhau (nếu p = q thì n = p² dễ phân tích)!")
    print(f"  ✓ p = {p}  → là số nguyên tố")
    print(f"  ✓ q = {q}  → là số nguyên tố")

    # ── Bước 1.2: Tính modulus n ────────────────────────────
    n = p * q
    print(f"\n[Bước 1.2] Tính modulus n:")
    print(f"  n = p × q = {p} × {q} = {n}")
    print(f"  n là cơ sở của cả khóa công khai lẫn khóa bí mật.")

    # ── Bước 1.3: Tính hàm Euler phi(n) ────────────────────
    phi_n = (p - 1) * (q - 1)
    print(f"\n[Bước 1.3] Tính hàm Euler φ(n):")
    print(f"  φ(n) = (p − 1) × (q − 1)")
    print(f"       = ({p} − 1) × ({q} − 1)")
    print(f"       = {p - 1} × {q - 1}")
    print(f"       = {phi_n}")
    print(f"  φ(n) = số nguyên trong [1, n] nguyên tố cùng nhau với n.")

    # ── Bước 1.4: Chọn số mũ công khai e ───────────────────
    e = find_valid_e(phi_n)
    print(f"\n[Bước 1.4] Chọn số mũ công khai e:")
    print(f"  e = {e}")
    print(f"  Điều kiện: 1 < {e} < {phi_n}  ✓")
    print(f"  Kiểm tra : gcd({e}, {phi_n}) = {gcd(e, phi_n)} = 1  ✓")

    # ── Bước 1.5: Tính khóa bí mật d ───────────────────────
    d = mod_inverse(e, phi_n)
    print(f"\n[Bước 1.5] Tính khóa bí mật d = e⁻¹ mod φ(n):")
    print(f"  d = {e}⁻¹ mod {phi_n} = {d}")
    print(f"  Kiểm tra: (e × d) mod φ(n) = ({e} × {d}) mod {phi_n} = {(e * d) % phi_n}  ✓")

    # ── Tổng kết ─────────────────────────────────────────────
    print(f"\n{'─' * 60}")
    print(f"  KẾT QUẢ: CẶP KHÓA RSA ĐÃ ĐƯỢC TẠO")
    print(f"{'─' * 60}")
    print(f"  Khóa Công khai (Public Key) : (e = {e},  n = {n})")
    print(f"  Khóa Bí mật   (Private Key) : (d = {d}, n = {n})")
    print(f"\n  ⚠  BÍ MẬT: Không bao giờ tiết lộ d = {d}, p = {p}, q = {q}, φ(n) = {phi_n}!")

    # ── Xây dựng dict để lưu JSON ────────────────────────────
    public_key = {
        "mode": "manual",
        "description": "Khóa công khai RSA — tạo thủ công (chỉ dùng cho demo)",
        "e": e,
        "n": n,
        "key_size_bits": n.bit_length(),
        "generation_params": {
            "p": p,
            "q": q,
            "phi_n": phi_n
        }
    }

    private_key = {
        "mode": "manual",
        "description": "Khóa bí mật RSA — KHÔNG CHIA SẺ FILE NÀY!",
        "d": d,
        "n": n,
        "key_size_bits": n.bit_length(),
        "generation_params": {
            "p": p,
            "q": q,
            "phi_n": phi_n,
            "e": e
        }
    }

    return public_key, private_key


# ============================================================
# PHẦN 3: CHẾ ĐỘ B — SINH KHÓA CHUẨN RSA (THỰC TẾ)
# ============================================================

def generate_keys_standard(key_size: int = 2048):
    """
    Sinh cặp khóa RSA chuẩn bằng thư viện cryptography.
    Đây là phương pháp đúng để dùng trong sản phẩm thực tế.
    """
    try:
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.backends import default_backend
    except ImportError:
        print("\n  ❌ Chưa cài đặt thư viện 'cryptography'.")
        print("     Chạy lệnh: pip install cryptography")
        sys.exit(1)

    sep = "=" * 60
    print(f"\n{sep}")
    print(f"  CHẾ ĐỘ B — SINH KHÓA RSA {key_size}-BIT CHUẨN")
    print(sep)

    print(f"\n[Bước 1.1] Đang sinh cặp khóa RSA {key_size}-bit, xin chờ...")
    print(f"  (Hệ thống sinh hai số nguyên tố lớn ngẫu nhiên p và q)")

    # Sinh private key với e = 65537 (số Fermat F4, giá trị chuẩn công nghiệp)
    private_key_obj = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    public_key_obj = private_key_obj.public_key()

    # Trích xuất tham số số học từ đối tượng khóa
    priv_numbers = private_key_obj.private_numbers()
    pub_numbers  = public_key_obj.public_numbers()

    n = pub_numbers.n
    e = pub_numbers.e
    d = priv_numbers.d
    p = priv_numbers.p
    q = priv_numbers.q

    print(f"\n[Bước 1.2] Thông tin cặp khóa vừa sinh:")
    print(f"  Kích thước khóa : {key_size} bit")
    print(f"  Số mũ công khai : e = {e}")
    print(f"  Modulus n       : {hex(n)[:18]}...{hex(n)[-10:]}  ({n.bit_length()} bit)")
    print(f"  Khóa bí mật d   : [ẩn — xem file private_key.json]")

    print(f"\n  ✅ Sinh khóa thành công!")
    print(f"  Khóa Công khai : (e = {e},  n = <{key_size}-bit số>)")
    print(f"  Khóa Bí mật   : (d = <{key_size}-bit số>, n = <{key_size}-bit số>)")

    public_key = {
        "mode": "standard",
        "description": "Khóa công khai RSA chuẩn — an toàn cho thực tế",
        "e": e,
        "n": n,
        "key_size_bits": key_size
    }

    private_key = {
        "mode": "standard",
        "description": "Khóa bí mật RSA chuẩn — KHÔNG CHIA SẺ FILE NÀY!",
        "d": d,
        "n": n,
        "p": p,
        "q": q,
        "key_size_bits": key_size
    }

    return public_key, private_key


# ============================================================
# PHẦN 4: HÀM CHÍNH — ĐIỀU PHỐI LUỒNG THỰC THI
# ============================================================

def main():
    sep = "=" * 60
    print(f"\n{sep}")
    print("  BƯỚC 1: TẠO CẶP KHÓA RSA")
    print(sep)

    print("\nChọn chế độ tạo khóa:")
    print("  [A]  Nhập thủ công p, q (số nhỏ, quan sát được phép tính)")
    print("  [B]  Tự động sinh khóa RSA 2048-bit chuẩn (cho thực tế)")

    choice = input("\nNhập lựa chọn (A/B) [mặc định: A]: ").strip().upper()
    if not choice:
        choice = "A"

    # ── Chế độ A: Thủ công ───────────────────────────────────
    if choice == "A":
        print("\n  Gợi ý các cặp số nguyên tố nhỏ để thử:")
        print("    p=61,  q=53  → n=3233  (ví dụ kinh điển trong sách giáo khoa)")
        print("    p=17,  q=19  → n=323")
        print("    p=101, q=103 → n=10403")
        print("    p=257, q=263 → n=67591")
        print()
        try:
            p = int(input("  Nhập p: ").strip())
            q = int(input("  Nhập q: ").strip())
        except ValueError:
            print("\n  ❌ Vui lòng nhập số nguyên hợp lệ!")
            sys.exit(1)

        try:
            public_key, private_key = generate_keys_manual(p, q)
        except ValueError as err:
            print(f"\n  ❌ Lỗi: {err}")
            sys.exit(1)

    # ── Chế độ B: Tự động ────────────────────────────────────
    elif choice == "B":
        print("\n  Kích thước khóa được hỗ trợ: 2048 / 3072 / 4096 bit")
        size_input = input("  Nhập kích thước khóa (bit) [mặc định: 2048]: ").strip()
        try:
            key_size = int(size_input) if size_input else 2048
        except ValueError:
            key_size = 2048
            print("  ⚠  Không hợp lệ, dùng mặc định 2048-bit.")

        public_key, private_key = generate_keys_standard(key_size)

    else:
        print("  ❌ Lựa chọn không hợp lệ! Chỉ nhập A hoặc B.")
        sys.exit(1)

    # ── Lưu khóa ra file JSON ────────────────────────────────
    DATA_DIR.mkdir(exist_ok=True)

    pub_path  = DATA_DIR / "public_key.json"
    priv_path = DATA_DIR / "private_key.json"

    with open(pub_path, "w", encoding="utf-8") as f:
        json.dump(public_key, f, indent=4, ensure_ascii=False)

    with open(priv_path, "w", encoding="utf-8") as f:
        json.dump(private_key, f, indent=4, ensure_ascii=False)

    print(f"\n[Lưu file]")
    print(f"  ✓ {pub_path}")
    print(f"  ✓ {priv_path}")
    print(f"\n{sep}")
    print("  ✅  HOÀN TẤT BƯỚC 1!")
    print("  →   Bước tiếp theo: python src/02_hash_firmware.py")
    print(f"{sep}\n")


if __name__ == "__main__":
    main()
