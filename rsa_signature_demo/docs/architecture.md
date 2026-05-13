# Kiến trúc Hệ thống Ký số Firmware RSA-PSS

## Tổng quan

Hệ thống bao gồm **hai phía** tham gia với vai trò khác nhau:

| Vai trò | Phía | Hành động | Khóa sử dụng |
|---------|------|-----------|--------------|
| **Nhà sản xuất (NSX)** | Gửi firmware | Ký (Sign) | **Private Key** (bí mật) |
| **Thiết bị nhận** | Nhận firmware | Xác thực (Verify) | **Public Key** (công khai) |

---

## Sơ đồ luồng dữ liệu tổng quan

```
╔══════════════════════════════════════════════════════════════════════════╗
║              PHÍA NHÀ SẢN XUẤT (NSX)  —  Môi trường bí mật             ║
╠══════════════════════════════════════════════════════════════════════════╣
║                                                                          ║
║  ┌─────────────────────────────────────┐                                 ║
║  │     BƯỚC 1: Tạo cặp khóa RSA       │  [01_generate_keys.py]          ║
║  │                                     │                                 ║
║  │   Chọn 2 số nguyên tố p, q         │                                 ║
║  │         n = p × q                   │                                 ║
║  │      φ(n) = (p-1)(q-1)             │                                 ║
║  │   Chọn e: gcd(e, φ(n)) = 1         │                                 ║
║  │   Tính d: e×d ≡ 1 (mod φ(n))       │                                 ║
║  └──────────┬──────────────────────────┘                                 ║
║             │                                                            ║
║      ┌──────┴──────────────────────┐                                     ║
║      │                             │                                     ║
║  ┌───▼───────────┐       ┌─────────▼────────────┐                       ║
║  │  Public Key   │       │    Private Key        │                       ║
║  │   (e, n)      │       │      (d, n)           │                       ║
║  │ public_key    │       │  private_key.json     │                       ║
║  │   .json       │       │  ← GIỮ BÍ MẬT TUYỆT  │                       ║
║  └───────────────┘       │       ĐỐI!            │                       ║
║        │                 └─────────┬────────────┘                       ║
║        │ Phân phối                 │                                     ║
║        │ rộng rãi                  │                                     ║
║        │                           ▼                                     ║
║        │              ┌─────────────────────────────┐                   ║
║        │              │  BƯỚC 2: Băm Firmware       │  [02_hash...py]   ║
║        │              │                             │                   ║
║        │              │  Đọc firmware.bin           │                   ║
║        │              │       ↓ SHA-256             │                   ║
║        │              │  mHash = H(firmware)        │                   ║
║        │              │  (32 bytes = 256 bit)       │                   ║
║        │              │  → firmware_hash.json       │                   ║
║        │              └──────────────┬──────────────┘                   ║
║        │                             │ mHash                            ║
║        │                             ▼                                  ║
║        │              ┌─────────────────────────────┐                   ║
║        │              │  BƯỚC 3: Đệm PSS và Ký     │  [03_sign...py]   ║
║        │              │                             │                   ║
║        │              │  salt ← os.urandom(32)      │                   ║
║        │              │  M' = [00×8]||mHash||salt   │                   ║
║        │              │  H  = SHA256(M')            │                   ║
║        │              │  EM = encode(H, salt, n)    │                   ║
║        │              │       ↓ RSA                 │                   ║
║        │              │  S  = EM^d mod n  ←──── d  │                   ║
║        │              │  → signature_output.json    │                   ║
║        │              └──────────────┬──────────────┘                   ║
║        │                             │                                  ║
╚════════╪═════════════════════════════╪══════════════════════════════════╝
         │                             │
         │   Phân phối qua Internet / Kênh truyền                        
         │   (Có thể bị nghe lén — nhưng KHÔNG thể giả mạo!)            
         │                             │
         │  ┌──────────────────────────▼──────────────────────────┐      
         │  │          firmware.bin  +  signature_output.json      │      
         │  │          (Bộ dữ liệu firmware + chữ ký đính kèm)    │      
         │  └──────────────────────────┬──────────────────────────┘      
         │                             │
╔════════╪═════════════════════════════╪══════════════════════════════════╗
║        │  PHÍA THIẾT BỊ NHẬN                                            ║
╠════════╪═════════════════════════════╪══════════════════════════════════╣
║        │                             │                                  ║
║        ▼                             ▼                                  ║
║  ┌───────────────────────────────────────────────────────────────────┐  ║
║  │          BƯỚC 4: Xác thực chữ ký          [04_verify...py]       │  ║
║  │                                                                   │  ║
║  │  ① Tính lại hash:  mHash_new = SHA256(firmware.bin nhận được)    │  ║
║  │                                                                   │  ║
║  │  ② Giải mã chữ ký: EM_actual = S^e mod n    ← dùng Public Key   │  ║
║  │                                                                   │  ║
║  │  ③ Tái tạo EM:     M' = [00×8] || mHash_new || salt (từ JSON)   │  ║
║  │                    H_new = SHA256(M')                             │  ║
║  │                    EM_expected = encode(H_new, salt, n)          │  ║
║  │                                                                   │  ║
║  │  ④ So sánh:        EM_actual  vs  EM_expected                    │  ║
║  │                              │                                    │  ║
║  │                    ┌─────────┴──────────┐                        │  ║
║  │                    │                    │                        │  ║
║  │                  BẰNG                KHÁC                       │  ║
║  │                    │                    │                        │  ║
║  │                    ▼                    ▼                        │  ║
║  │           ✅ HỢP LỆ             ❌ BỊ GIẢ MẠO                   │  ║
║  │      Cài đặt firmware        Từ chối firmware                    │  ║
║  └───────────────────────────────────────────────────────────────────┘  ║
╚══════════════════════════════════════════════════════════════════════════╝
```

---

## Vai trò các file dữ liệu trung gian

```
data/
│
├── firmware.bin              ← ĐẦU VÀO: File firmware cần bảo vệ
│                                (Binary, kích thước tùy ý)
│
├── public_key.json           ← KHÓA CÔNG KHAI — chia sẻ rộng rãi
│   {                             Ai cũng có thể xác thực với khóa này
│     "mode":  "manual/standard",
│     "e":     <số mũ công khai>,
│     "n":     <modulus lớn>
│   }
│
├── private_key.json          ← KHÓA BÍ MẬT — chỉ NSX giữ
│   {                             Lộ khóa này = mất toàn bộ bảo mật!
│     "mode":  "manual/standard",
│     "d":     <số mũ bí mật>,
│     "n":     <modulus lớn>
│   }
│
├── firmware_hash.json        ← KẾT QUẢ BƯỚC 2: Dấu vân tay firmware
│   {
│     "hash_algorithm": "SHA-256",
│     "hash_hex": "abc123def456..."  ← 64 ký tự = 256 bit
│   }
│
└── signature_output.json     ← KẾT QUẢ BƯỚC 3: Gói chữ ký hoàn chỉnh
    {                              (Đính kèm firmware khi phân phối)
      "algorithm":     "RSA-PSS-SHA256",
      "signature_hex": "deadbeef...",    ← Chữ ký S
      "salt_hex":      "cafebabe...",    ← Salt dùng trong PSS
    }
```

---

## Tại sao RSA-PSS an toàn hơn RSA thuần?

| Đặc điểm | RSA thuần (PKCS#1 v1.5) | RSA-PSS |
|-----------|-------------------------|---------|
| Tính xác định | Ký 2 lần → **cùng** chữ ký | Ký 2 lần → **khác** chữ ký |
| Chống tấn công thống kê | Yếu — dễ phân tích pattern | Mạnh — salt ngẫu nhiên phá vỡ pattern |
| Bằng chứng bảo mật | Không có chứng minh hình thức | Có **provable security** (bằng chứng toán học) |
| Tiêu chuẩn áp dụng | PKCS#1 v1.5 (cũ, hạn chế dùng) | **RFC 8017, FIPS 186-5** (khuyến nghị hiện tại) |
| Độ phức tạp triển khai | Đơn giản | Phức tạp hơn (cần MGF1) |

---

## Các mối đe dọa mà hệ thống bảo vệ được

| Kịch bản tấn công | Được bảo vệ? | Giải thích |
|-------------------|:------------:|------------|
| Kẻ tấn công sửa 1 byte firmware | ✅ Có | Hash thay đổi → EM_expected ≠ EM_actual |
| Kẻ tấn công thay toàn bộ firmware | ✅ Có | Không có Private Key → không tạo được chữ ký hợp lệ |
| Kẻ tấn công phát lại chữ ký cũ | ✅ Có | Chữ ký gắn với hash của firmware cụ thể |
| Kẻ tấn công đoán chữ ký | ✅ Có | Không gian chữ ký quá lớn (2^2048 với RSA-2048) |
| Nghe lén kênh truyền | ✅ Có | Public Key là công khai — không cần che giấu |
| Từ chối chữ ký (Non-repudiation) | ✅ Có | Chỉ Private Key mới tạo được chữ ký hợp lệ |
