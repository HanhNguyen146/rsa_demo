# Chi tiết từng bước của Quy trình Ký số RSA-PSS

## Tổng quan nhanh

| Bước | Script | Đầu vào | Xử lý | Đầu ra |
|------|--------|---------|-------|--------|
| 1 | `01_generate_keys.py` | p, q (thủ công) hoặc tham số tự động | Tạo cặp khóa RSA | `public_key.json`, `private_key.json` |
| 2 | `02_hash_firmware.py` | `firmware.bin` | SHA-256 | `firmware_hash.json` |
| 3 | `03_sign_firmware.py` | `firmware_hash.json`, `private_key.json` | PSS Padding + RSA Sign | `signature_output.json` |
| 4 | `04_verify_signature.py` | `firmware.bin`, `public_key.json`, `signature_output.json` | PSS Verify + RSA Verify | Kết quả in ra màn hình |

---

## BƯỚC 1 — `01_generate_keys.py`: Tạo cặp khóa RSA

### Mục đích
Sinh cặp khóa bất đối xứng RSA. Khóa công khai được chia sẻ tự do; khóa bí mật được giữ an toàn bởi NSX.

### File đầu vào cần chuẩn bị
*(Không cần file đầu vào — script tự tương tác với người dùng)*

| Chế độ | Thông tin cần cung cấp |
|--------|------------------------|
| **A — Thủ công** | Hai số nguyên tố p, q nhập từ bàn phím |
| **B — Tự động** | Chọn kích thước khóa: 2048 / 3072 / 4096 bit |

### Thuật toán xử lý

**Chế độ A (Thủ công — quan sát phép tính):**

```
Bước 1.1  Kiểm tra: is_prime(p) và is_prime(q) và p ≠ q

Bước 1.2  n = p × q
          (n là modulus — là cơ sở của cả 2 khóa)

Bước 1.3  φ(n) = (p − 1) × (q − 1)
          (Hàm Euler — số lượng số nguyên tố cùng nhau với n trong [1,n])

Bước 1.4  Chọn e: 1 < e < φ(n), gcd(e, φ(n)) = 1
          (Ưu tiên e = 65537 = 2^16 + 1, số Fermat F4)

Bước 1.5  d = e⁻¹ mod φ(n)   [Dùng thuật toán Euclid mở rộng]
          Kiểm tra: (e × d) mod φ(n) = 1
```

**Chế độ B (Tự động — thực tế):**
```
private_key = rsa.generate_private_key(
    public_exponent = 65537,
    key_size        = 2048,       # hoặc 3072 / 4096
)
→ Thư viện tự chọn p, q ngẫu nhiên lớn, thực hiện kiểm tra Miller-Rabin
```

### File xuất ra

**`data/public_key.json`**
```json
{
    "mode": "manual",
    "description": "Khóa công khai RSA — tạo thủ công (chỉ dùng cho demo)",
    "e": 65537,
    "n": 3233,
    "key_size_bits": 12,
    "generation_params": {
        "p": 61,
        "q": 53,
        "phi_n": 3120
    }
}
```

**`data/private_key.json`**
```json
{
    "mode": "manual",
    "description": "Khóa bí mật RSA — KHÔNG CHIA SẺ FILE NÀY!",
    "d": 2753,
    "n": 3233,
    "key_size_bits": 12,
    "generation_params": {
        "p": 61,
        "q": 53,
        "phi_n": 3120,
        "e": 65537
    }
}
```

### Ý nghĩa toán học
- **Khóa công khai (e, n)**: Dùng để XÁC THỰC — ai cũng có thể dùng
- **Khóa bí mật (d, n)**: Dùng để KÝ — chỉ NSX giữ
- **Mối liên hệ**: `(m^d)^e ≡ m (mod n)` — đây là tính chất RSA cốt lõi
- **Bảo mật**: Tìm d từ (e, n) tương đương phân tích n = p×q — bài toán cực khó

---

## BƯỚC 2 — `02_hash_firmware.py`: Băm file firmware

### Mục đích
Tạo ra "dấu vân tay số" (digital fingerprint) cố định 256 bit cho firmware, bất kể firmware lớn bao nhiêu. RSA không thể ký trực tiếp dữ liệu lớn — phải ký trên hash.

### File đầu vào cần chuẩn bị

| File | Vị trí | Mô tả |
|------|--------|-------|
| `firmware.bin` | `data/firmware.bin` | File firmware nhị phân cần bảo vệ |

*(Nếu không có firmware.bin, script tự tạo file mẫu để demo)*

### Thuật toán xử lý (SHA-256)

```
Đọc firmware.bin theo từng chunk 64 KB
         ↓
Cập nhật trạng thái SHA-256 với mỗi chunk:
  SHA-256 dùng 64 vòng lặp nén (compression rounds)
  Mỗi vòng dùng 8 biến trạng thái 32-bit (a, b, c, d, e, f, g, h)
         ↓
Kết quả: 32 bytes = 256 bit = 64 ký tự hex
```

**Tính chất của SHA-256 được minh họa trong script:**

| Tính chất | Ý nghĩa |
|-----------|---------|
| **Tất định (Deterministic)** | Cùng firmware → luôn cùng hash |
| **Một chiều (One-way)** | Không thể tìm ngược firmware từ hash |
| **Chống va chạm (Collision resistant)** | Cực kỳ khó tìm 2 file cùng hash |
| **Avalanche Effect** | 1 bit thay đổi → ~50% bit hash thay đổi |

### File xuất ra

**`data/firmware_hash.json`**
```json
{
    "description": "Kết quả băm SHA-256 của file firmware",
    "input_file": "firmware.bin",
    "input_file_size_bytes": 512,
    "hash_algorithm": "SHA-256",
    "hash_output_bits": 256,
    "hash_output_bytes": 32,
    "hash_hex": "a3f1c9b2e7d4850f2c1a8b3d6e9f0c2d5a8b1e4f7c0d3e6a9b2c5d8e1f4a7b0",
    "hash_bytes_decimal": [163, 241, 201, 178, ...]
}
```

### Điểm quan sát thú vị khi demo
Thay đổi 1 ký tự trong `firmware.bin`, chạy lại bước 2 → hash hoàn toàn khác. Đây chứng minh firmware không thể bị sửa mà không bị phát hiện.

---

## BƯỚC 3 — `03_sign_firmware.py`: Thêm đệm PSS và ký số

### Mục đích
Thực hiện quy trình ký RSA-PSS hoàn chỉnh: thêm Salt ngẫu nhiên để tạo tính ngẫu nhiên hóa, sau đó ký bằng Private Key.

### File đầu vào cần chuẩn bị

| File | Vị trí | Nội dung cần |
|------|--------|-------------|
| `firmware_hash.json` | `data/firmware_hash.json` | Trường `hash_hex` |
| `private_key.json` | `data/private_key.json` | Trường `d`, `n`, `mode` |

### Thuật toán xử lý

**PSS Encoding (Probabilistic Signature Scheme):**

```
── Đầu vào: mHash = SHA256(firmware), d, n ──────────────────────

Bước 3.1  salt = os.urandom(8)   ← 8 byte ngẫu nhiên hoàn toàn
          (Mỗi lần gọi urandom() cho kết quả khác nhau)

Bước 3.2  Tạo M' (Message Representative):
          M' = [0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00]
             ‖ mHash                                      (32 bytes)
             ‖ salt                                       (8 bytes)
          (8 byte 0x00 đầu là quy định PSS, tránh va chạm hash)

Bước 3.3  H = SHA256(M')    ← "Witness hash" (32 bytes)
          H là hash của (padding ‖ mHash ‖ salt)

Bước 3.4  EM = int(H) mod n  ← Encoded Message (phù hợp với n)
          (PSS chuẩn dùng MGF1 mask phức tạp hơn,
           nhưng ý tưởng về salt là giống nhau)

Bước 3.5  S = EM^d mod n     ← Chữ ký số (RSA decryption)
          (d là khóa bí mật, chỉ NSX biết)

── Đầu ra: S (chữ ký), salt (cần lưu để xác thực) ─────────────
```

**Demo ký 2 lần — chứng minh tính ngẫu nhiên:**
```
Lần 1: salt1 = random() → EM1 = f(mHash, salt1) → S1 = EM1^d mod n
Lần 2: salt2 = random() → EM2 = f(mHash, salt2) → S2 = EM2^d mod n

salt1 ≠ salt2  →  EM1 ≠ EM2  →  S1 ≠ S2
(Dù cùng firmware, 2 chữ ký KHÁC NHAU — đây là ưu điểm của PSS!)
```

### File xuất ra

**`data/signature_output.json`** — gói dữ liệu đính kèm firmware khi phân phối
```json
{
    "mode": "manual",
    "description": "Chữ ký số RSA-PSS (demo số nguyên tố nhỏ)",
    "algorithm": "Simplified-RSA-PSS-SHA256",
    "original_hash_hex": "a3f1c9b2...",
    "salt_hex": "cafebabe01020304",
    "salt_bytes_decimal": [202, 254, 186, 190, 1, 2, 3, 4],
    "witness_H_hex": "f7e3d2c1b0a9...",
    "encoded_message_int": 1847,
    "signature_int": 2943,
    "signature_hex": "b7f",
    "signing_demo": {
        "note": "Ký 2 lần với 2 salt khác nhau để chứng minh PSS Randomization",
        "round1": { "salt_hex": "cafebabe01020304", "signature_int": 2943 },
        "round2": { "salt_hex": "deadbeef05060708", "signature_int": 1156 },
        "signatures_are_different": true
    }
}
```

### Điểm quan trọng
- `salt_hex` **phải được đính kèm** cùng chữ ký (thiết bị nhận cần salt để xác thực)
- Với chế độ B (chuẩn), salt được nhúng bên trong cấu trúc chữ ký PSS — thư viện tự quản lý

---

## BƯỚC 4 — `04_verify_signature.py`: Xác thực chữ ký

### Mục đích
Phía thiết bị nhận kiểm tra: firmware có thật sự đến từ NSX hợp lệ không? Nội dung có bị sửa không?

### File đầu vào cần chuẩn bị

| File | Vị trí | Dùng để |
|------|--------|---------|
| `firmware.bin` | `data/firmware.bin` | Tính lại hash để so sánh |
| `public_key.json` | `data/public_key.json` | Giải mã chữ ký S → EM_actual |
| `signature_output.json` | `data/signature_output.json` | Lấy S, salt, original_hash |

### Thuật toán xác thực

```
── Đầu vào: firmware.bin, (e, n), S, salt ───────────────────────

Bước 4.1  mHash_new = SHA256(firmware.bin nhận được)

Bước 4.2  EM_actual = S^e mod n
          (RSA decryption với Public Key — bất kỳ ai cũng làm được)

Bước 4.3  Tái tạo EM_expected:
          M' = [0x00 × 8] ‖ mHash_new ‖ salt
          H_new = SHA256(M')
          EM_expected = int(H_new) mod n

Bước 4.4  So sánh:
          EM_actual == EM_expected ?
            CÓ  → ✅ Hợp lệ  (firmware chính hãng, không bị sửa)
            KHÔNG → ❌ Giả mạo (từ chối!)

── Đầu ra: Thông báo kết quả + demo phát hiện giả mạo ──────────
```

**Tại sao xác thực hoạt động đúng?**

Nếu firmware không bị sửa:
```
mHash_new = SHA256(firmware gốc) = mHash_original

EM_actual   = S^e mod n
            = (EM^d mod n)^e mod n
            = EM^(d×e) mod n
            = EM mod n          [vì d×e ≡ 1 (mod φ(n))]
            = EM

EM_expected = int(SHA256([00×8]||mHash_new||salt)) mod n
            = int(SHA256([00×8]||mHash_original||salt)) mod n
            = EM   [vì salt giống nhau]

→ EM_actual == EM_expected ✅
```

Nếu firmware bị sửa:
```
mHash_new ≠ mHash_original

EM_expected = int(SHA256([00×8]||mHash_new||salt)) mod n
            ≠ EM   [hash thay đổi → EM khác]

→ EM_actual ≠ EM_expected ❌
```

### Output ra màn hình

```
============================================================
  ✅  KẾT QUẢ: CHỮ KÝ HỢP LỆ — FIRMWARE AN TOÀN
  ────────────────────────────────────────────────────────
  Firmware này đã được xác nhận:
    • Tính xác thực : đến từ đúng nhà sản xuất (NSX)
    • Tính toàn vẹn : nội dung KHÔNG bị chỉnh sửa
    → An toàn để cài đặt lên thiết bị.
============================================================
```

hoặc:

```
============================================================
  ❌  KẾT QUẢ: CHỮ KÝ KHÔNG HỢP LỆ — TỪ CHỐI FIRMWARE!
  ────────────────────────────────────────────────────────
  Firmware bị từ chối vì có thể:
    • Đến từ nguồn không xác thực (giả mạo NSX)
    • Bị chỉnh sửa sau khi NSX đã ký
    → KHÔNG cài đặt — nguy hiểm cho thiết bị!
============================================================
```

---

## Hướng dẫn chạy toàn bộ demo

### Cài đặt môi trường
```bash
cd rsa_signature_demo
pip install -r requirements.txt
```

### Chạy từng bước
```bash
# Bước 1: Tạo khóa (chọn A với p=61, q=53 để thấy phép tính)
python src/01_generate_keys.py

# Bước 2: Băm firmware
python src/02_hash_firmware.py

# Bước 3: Ký số
python src/03_sign_firmware.py

# Bước 4: Xác thực
python src/04_verify_signature.py
```

### Thực nghiệm gợi ý cho sinh viên

| Thực nghiệm | Cách làm | Kết quả mong đợi |
|-------------|----------|------------------|
| Thay đổi firmware sau khi ký | Sửa 1 ký tự trong `firmware.bin`, chạy lại bước 4 | ❌ Xác thực thất bại |
| Ký 2 lần cùng firmware | Chạy bước 3 hai lần, so sánh `signature_output.json` | Chữ ký khác nhau (PSS) |
| Dùng khóa sai | Sửa `e` trong `public_key.json`, chạy bước 4 | ❌ Xác thực thất bại |
| Số nguyên tố khác nhau | Chạy bước 1 với p=17, q=19 thay vì p=61, q=53 | Khóa khác, d khác |
| So sánh chế độ A và B | Chạy bước 1 chọn B, làm toàn bộ quy trình | Kết quả tương tự nhưng số lớn hơn nhiều |
