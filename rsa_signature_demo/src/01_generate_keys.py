#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Buoc 1: Tao cap khoa RSA tu hai so nguyen to p va q nhap thu cong.

Output:
  data/public_key.json   -- {"e": ..., "n": ...}
  data/private_key.json  -- {"d": ..., "n": ...}
"""

import json
import math
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"


def is_prime(n: int) -> bool:
    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    for i in range(3, int(math.isqrt(n)) + 1, 2):
        if n % i == 0:
            return False
    return True


def extended_gcd(a: int, b: int):
    if a == 0:
        return b, 0, 1
    g, x, y = extended_gcd(b % a, a)
    return g, y - (b // a) * x, x


def gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return a


def mod_inverse(e: int, phi_n: int) -> int:
    g, x, _ = extended_gcd(e % phi_n, phi_n)
    if g != 1:
        raise ValueError(f"Nghich dao modular khong ton tai: gcd({e}, {phi_n}) = {g}")
    return x % phi_n


def find_valid_e(phi_n: int) -> int:
    for candidate in [65537, 257, 17, 5, 3]:
        if candidate < phi_n and gcd(candidate, phi_n) == 1:
            return candidate
    for e in range(2, phi_n):
        if gcd(e, phi_n) == 1:
            return e
    raise ValueError("Khong tim duoc e hop le.")


def main():
    print("Buoc 1: Nhap hai so nguyen to p va q.")
    try:
        p = int(input("  p = ").strip())
        q = int(input("  q = ").strip())
    except ValueError:
        print("  Loi: Vui long nhap so nguyen hop le.")
        sys.exit(1)

    print("Buoc 2: Kiem tra tinh nguyen to.")
    if not is_prime(p):
        print(f"  Loi: p = {p} khong phai so nguyen to.")
        sys.exit(1)
    if not is_prime(q):
        print(f"  Loi: q = {q} khong phai so nguyen to.")
        sys.exit(1)
    if p == q:
        print("  Loi: p va q phai khac nhau.")
        sys.exit(1)
    print(f"  p = {p}  -> nguyen to")
    print(f"  q = {q}  -> nguyen to")

    print("Buoc 3: Tinh cac tham so.")
    n     = p * q
    phi_n = (p - 1) * (q - 1)
    print(f"  n      = {p} x {q} = {n}")
    print(f"  phi(n) = ({p}-1) x ({q}-1) = {p - 1} x {q - 1} = {phi_n}")

    try:
        e = find_valid_e(phi_n)
        d = mod_inverse(e, phi_n)
    except ValueError as err:
        print(f"  Loi: {err}")
        sys.exit(1)

    print(f"  e = {e}   [gcd(e, phi(n)) = {gcd(e, phi_n)}]")
    print(f"  d = {d}   [(e x d) mod phi(n) = {(e * d) % phi_n}]")

    print("Buoc 4: Luu khoa vao file.")
    DATA_DIR.mkdir(exist_ok=True)

    with open(DATA_DIR / "public_key.json", "w", encoding="utf-8") as f:
        json.dump({"e": e, "n": n}, f, indent=4)
    with open(DATA_DIR / "private_key.json", "w", encoding="utf-8") as f:
        json.dump({"d": d, "n": n}, f, indent=4)

    print("  public_key.json  -> OK")
    print("  private_key.json -> OK")
    print("Hoan tat. Chay tiep: python src/02_hash_firmware.py")


if __name__ == "__main__":
    main()
