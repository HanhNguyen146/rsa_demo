# Chi tiet tung buoc cua Quy trinh Ky so RSA

## Tong quan nhanh

| Buoc | Script | Dau vao | Xu ly | Dau ra |
|------|--------|---------|-------|--------|
| 1 | `01_generate_keys.py` | p, q nhap thu cong | Tinh n, phi(n), e, d | `public_key.json`, `private_key.json` |
| 2 | `02_hash_firmware.py` | `firmware.bin` | Bam du lieu | `firmware_hash.json` |
| 3 | `03_sign_firmware.py` | `firmware_hash.json`, `private_key.json` | S = H^d mod n | `signature_output.json` |
| 4 | `04_verify_signature.py` | `firmware.bin`, `public_key.json`, `signature_output.json` | H' = S^e mod n, so sanh | In ket qua ra man hinh |

---

## BUOC 1 -- `01_generate_keys.py`: Tao cap khoa RSA

### Muc dich
Sinh cap khoa bat doi xung RSA tu hai so nguyen to p, q do nguoi dung nhap thu cong.
Khoa cong khai duoc chia se tu do; khoa bi mat duoc giu an toan boi NSX.

### Dau vao
Khong can file -- script tuong tac truc tiep voi nguoi dung qua ban phim.

| Thong tin can nhap | Mo ta |
|--------------------|-------|
| p | So nguyen to thu nhat |
| q | So nguyen to thu hai (p != q) |

### Thuat toan xu ly

```
Buoc 1.1  Kiem tra: is_prime(p) va is_prime(q) va p != q

Buoc 1.2  n = p x q
          (n la modulus -- la co so cua ca 2 khoa)

Buoc 1.3  phi(n) = (p - 1) x (q - 1)
          (Ham Euler -- so luong so nguyen to cung nhau voi n trong [1, n])

Buoc 1.4  Chon e: 1 < e < phi(n), gcd(e, phi(n)) = 1
          (Thu theo thu tu: 65537, 257, 17, 5, 3, ...)

Buoc 1.5  d = e^(-1) mod phi(n)   [Thuat toan Euclid mo rong]
          Kiem tra: (e x d) mod phi(n) = 1
```

### File xuat ra

**`data/public_key.json`**
```json
{
    "e": 257,
    "n": 3233
}
```

**`data/private_key.json`**
```json
{
    "d": 2513,
    "n": 3233
}
```

### Y nghia toan hoc
- **Khoa cong khai (e, n)**: Dung de XAC THUC -- ai cung co the dung
- **Khoa bi mat (d, n)**: Dung de KY -- chi NSX giu
- **Moi lien he**: (m^d)^e = m (mod n) -- tinh chat RSA cot loi
- **Bao mat**: Tim d tu (e, n) tuong duong phan tich n = p x q -- bai toan cuc kho

---

## BUOC 2 -- `02_hash_firmware.py`: Bam file firmware

### Muc dich
Tao ra "dau van tay so" co dinh 256 bit cho firmware, bat ke firmware lon bao nhieu.
Buoc ky chi lam viec voi so nguyen -- khong the ky truc tiep du lieu lon -- phai ky tren ban bam.

### File dau vao

| File | Vi tri | Mo ta |
|------|--------|-------|
| `firmware.bin` | `data/firmware.bin` | File firmware nhi phan can bao ve |

*(Neu khong co firmware.bin, script tu tao file mau de demo)*

### Thuat toan xu ly

```
Doc firmware.bin
      |
Ap dung ham bam (SHA-256):
  Dau vao: du lieu tuy y
  Dau ra:  32 bytes = 256 bit = 64 ky tu hex
      |
Ket qua: hash_hex (chuoi 64 ky tu hex)
```

**Tinh chat duoc the hien:**

| Tinh chat | Y nghia |
|-----------|---------|
| **Tat dinh** | Cung firmware -> luon cung ban bam |
| **Mot chieu** | Khong the tim nguoc firmware tu ban bam |
| **Chong va cham** | Cuc ky kho tim 2 file cung ban bam |
| **Hieu ung tuyết lo** | 1 bit thay doi -> ~50% bit ban bam thay doi |

### File xuat ra

**`data/firmware_hash.json`**
```json
{
    "hash_hex": "3611998e9e53da8f4e1f2b30dfcead1d8b2d5a3c6e9f0c1d4a7b0e3f6c9d2a5"
}
```

### Diem quan sat thu vi khi demo
Thay doi 1 ky tu trong `firmware.bin`, chay lai buoc 2 --> ban bam hoan toan khac.
Dieu nay chung minh firmware khong the bi sua ma khong bi phat hien.

---

## BUOC 3 -- `03_sign_firmware.py`: Ky so thuan tuy

### Muc dich
Ky ban bam bang Private Key theo cong thuc thuan tuy: **S = H^d mod n**.

### File dau vao

| File | Vi tri | Noi dung can |
|------|--------|-------------|
| `firmware_hash.json` | `data/firmware_hash.json` | Truong `hash_hex` |
| `private_key.json` | `data/private_key.json` | Truong `d`, `n` |

### Thuat toan xu ly

```
Dau vao: hash_hex (chuoi hex tu buoc 2), d, n

Buoc 3.1  Doc hash_hex tu firmware_hash.json

Buoc 3.2  Chuyen ban bam ve so nguyen:
          H = int(hash_hex, 16) mod n
          (Ap dung mod n vi n co the nho hon 2^256 khi dung so nguyen to nho)

Buoc 3.3  Ky so:
          S = H^d mod n     <- RSA sign voi Private Key

Dau ra: S (chu ky so), luu kem H de tham khao
```

**Giai thich buoc "mod n":**

Khi nguoi dung nhap p, q nho (vi du p=61, q=53 -> n=3233), n chi co 12 bit.
Ban bam co 256 bit. int(hash) se lon hon n, do do can ap dung mod n de dua
gia tri ve pham vi hop le [0, n) truoc khi tinh mu.

### File xuat ra

**`data/signature_output.json`**
```json
{
    "hash_int":      1364,
    "signature_int": 1903,
    "signature_hex": "76f"
}
```

| Truong | Y nghia |
|--------|---------|
| `hash_int` | H = int(hash_hex) mod n -- gia tri dau vao cho phep ky |
| `signature_int` | S = H^d mod n -- chu ky so chinh thuc |
| `signature_hex` | Bieu dien hex cua S |

---

## BUOC 4 -- `04_verify_signature.py`: Xac thuc chu ky

### Muc dich
Phia thiet bi nhan kiem tra: firmware co that su den tu NSX hop le khong? Noi dung co bi sua khong?

### File dau vao

| File | Vi tri | Dung de |
|------|--------|---------|
| `firmware.bin` | `data/firmware.bin` | Tinh lai ban bam de so sanh |
| `public_key.json` | `data/public_key.json` | Giai ma chu ky S -> H' |
| `signature_output.json` | `data/signature_output.json` | Lay S |

### Thuat toan xac thuc

```
Dau vao: firmware.bin nhan duoc, (e, n), S

Buoc 4.1  Tinh lai ban bam firmware nhan duoc:
          H_new = int(hash(firmware.bin)) mod n

Buoc 4.2  Giai ma chu ky bang Public Key:
          H' = S^e mod n
          (Bat ky ai co Public Key deu lam duoc buoc nay)

Buoc 4.3  So sanh:
          H' == H_new ?
            CO  -> Chu ky hop le.
            KHONG -> Chu ky khong hop le.

Dau ra: In ket qua ra man hinh + demo phat hien gia mao
```

**Tai sao xac thuc hoat dong dung?**

Neu firmware khong bi sua:
```
H_new = int(hash(firmware goc)) mod n = H

H'    = S^e mod n
      = (H^d mod n)^e mod n
      = H^(d x e) mod n
      = H mod n          [vi d x e = 1 (mod phi(n))]
      = H

-> H' == H_new  [Hop le]
```

Neu firmware bi sua:
```
H_new = int(hash(firmware bi sua)) mod n  !=  H
        (ban bam thay doi hoan toan khi firmware thay doi)

H'    = S^e mod n = H  (khong doi)

-> H' != H_new  [Khong hop le]
```

### Output ra man hinh

```
Chu ky hop le.
```

hoac:

```
Chu ky khong hop le.
```

---

## Huong dan chay toan bo demo

### Chay tung buoc

```bash
# Buoc 1: Tao khoa (vi du: p=61, q=53)
python src/01_generate_keys.py

# Buoc 2: Bam firmware
python src/02_hash_firmware.py

# Buoc 3: Ky so
python src/03_sign_firmware.py

# Buoc 4: Xac thuc
python src/04_verify_signature.py
```

### Goi y so nguyen to nho de quan sat phep tinh

| p | q | n | phi(n) | e | d |
|---|---|---|--------|---|---|
| 61 | 53 | 3233 | 3120 | 257 | 2513 |
| 17 | 19 | 323 | 288 | 5 | 173 |
| 101 | 103 | 10403 | 10200 | 17 | 1800 |
| 257 | 263 | 67591 | 67072 | 3 | 44715 |

### Thuc nghiem goi y cho sinh vien

| Thuc nghiem | Cach lam | Ket qua mong doi |
|-------------|----------|------------------|
| Thay doi firmware sau khi ky | Sua 1 ky tu trong `firmware.bin`, chay lai buoc 4 | Chu ky khong hop le. |
| Dung khoa sai | Sua `e` trong `public_key.json`, chay buoc 4 | Chu ky khong hop le. |
| So nguyen to khac nhau | Chay buoc 1 voi p=17, q=19 thay vi p=61, q=53 | Khoa khac, d khac |
| Quan sat gia tri H | Xem `hash_int` trong signature_output.json | H nho hon n do mod |
| Xac nhan cong thuc | Tinh tay: H^d mod n roi H'^e mod n | Ket qua phai khop |
