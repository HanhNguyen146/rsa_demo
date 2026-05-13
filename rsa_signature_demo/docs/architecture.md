# Kien truc He thong Ky so Firmware RSA

## Tong quan

He thong gom **hai phia** tham gia voi vai tro khac nhau:

| Vai tro | Phia | Hanh dong | Khoa su dung |
|---------|------|-----------|--------------|
| **Nha san xuat (NSX)** | Gui firmware | Ky (Sign) | **Private Key** (bi mat) |
| **Thiet bi nhan** | Nhan firmware | Xac thuc (Verify) | **Public Key** (cong khai) |

---

## So do luong du lieu tong quan

```
+=========================================================================+
|              PHIA NHA SAN XUAT (NSX)  --  Moi truong bi mat            |
+=========================================================================+
|                                                                         |
|  +--------------------------------------+                               |
|  |    BUOC 1: Tao cap khoa RSA          |  [01_generate_keys.py]       |
|  |                                      |                              |
|  |   Nhap hai so nguyen to p, q        |                              |
|  |         n = p x q                    |                              |
|  |      phi(n) = (p-1)(q-1)            |                              |
|  |   Chon e: gcd(e, phi(n)) = 1        |                              |
|  |   Tinh d: e x d = 1 (mod phi(n))    |                              |
|  +---------------+----------------------+                               |
|                  |                                                      |
|         +--------+------------------+                                   |
|         |                          |                                    |
|  +------v----------+    +----------v-----------+                        |
|  |  Public Key     |    |    Private Key       |                        |
|  |   (e, n)        |    |      (d, n)          |                        |
|  | public_key.json |    |  private_key.json    |                        |
|  |                 |    |  <- GIU BI MAT!      |                        |
|  +-----------------+    +----------+-----------+                        |
|        |                           |                                    |
|        |  Phan phoi                |                                    |
|        |  rong rai                 v                                    |
|        |              +---------------------------+                     |
|        |              |  BUOC 2: Bam Firmware    |  [02_hash...py]     |
|        |              |                           |                     |
|        |              |  Doc firmware.bin         |                     |
|        |              |       |                   |                     |
|        |              |  H_hex = hash(firmware)   |                     |
|        |              |  -> firmware_hash.json    |                     |
|        |              +-------------+-------------+                     |
|        |                            |  H_hex                           |
|        |                            v                                   |
|        |              +---------------------------+                     |
|        |              |  BUOC 3: Ky so           |  [03_sign...py]     |
|        |              |                           |                     |
|        |              |  H = int(H_hex) mod n     |                     |
|        |              |       |                   |                     |
|        |              |  S = H^d mod n  <---- d   |                     |
|        |              |  -> signature_output.json |                     |
|        |              +-------------+-------------+                     |
|        |                            |                                   |
+========+============================+===================================+
         |                            |
         |   Phan phoi qua Internet / Kenh truyen
         |   (Co the bi nghe len -- nhung KHONG the gia mao!)
         |                            |
         |  +--------------------------v--------------------------+
         |  |      firmware.bin  +  signature_output.json        |
         |  |      (Bo du lieu firmware + chu ky dinh kem)       |
         |  +---------------------------+------------------------+
         |                             |
+========+=============================+==================================+
|        |  PHIA THIET BI NHAN                                            |
+========+=============================+==================================+
         |                             |
         v                             v
|  +------------------------------------------------------------------------+  |
|  |          BUOC 4: Xac thuc chu ky         [04_verify...py]             |  |
|  |                                                                        |  |
|  |  (1) Tinh lai ban bam: H_new = int(hash(firmware.bin nhan duoc)) % n  |  |
|  |                                                                        |  |
|  |  (2) Giai ma chu ky:   H' = S^e mod n   <- dung Public Key (e, n)     |  |
|  |                                                                        |  |
|  |  (3) So sanh:          H'  vs  H_new                                  |  |
|  |                                 |                                      |  |
|  |                       +---------+---------+                            |  |
|  |                       |                   |                            |  |
|  |                    BANG NHAU          KHAC NHAU                       |  |
|  |                       |                   |                            |  |
|  |                       v                   v                            |  |
|  |              [Chu ky hop le.]    [Chu ky khong hop le.]               |  |
|  |              Cai dat firmware    Tu choi firmware                      |  |
|  +------------------------------------------------------------------------+  |
```

---

## Vai tro cac file du lieu trung gian

```
data/
|
+-- firmware.bin              <- DAU VAO: File firmware can bao ve
|
+-- public_key.json           <- KHOA CONG KHAI -- chia se rong rai
|   {
|     "e": <so mu cong khai>,
|     "n": <modulus>
|   }
|
+-- private_key.json          <- KHOA BI MAT -- chi NSX giu
|   {
|     "d": <so mu bi mat>,
|     "n": <modulus>
|   }
|
+-- firmware_hash.json        <- KET QUA BUOC 2: Ban bam firmware
|   {
|     "hash_hex": "abc123..."  <- 64 ky tu = 256 bit
|   }
|
+-- signature_output.json     <- KET QUA BUOC 3: Chu ky so
    {
      "hash_int":      <H = int(hash) mod n>,
      "signature_int": <S = H^d mod n>,
      "signature_hex": "..."
    }
```

---

## Cong thuc toan hoc cot loi

| Buoc | Phia | Cong thuc | Mo ta |
|------|------|-----------|-------|
| Tao khoa | NSX | n = p x q, phi(n) = (p-1)(q-1) | Modulus va ham Euler |
| Tao khoa | NSX | e x d = 1 (mod phi(n)) | Khoa bi mat d la nghich dao cua e |
| Bam | NSX | H_hex = hash(firmware) | Tao ban bam |
| Ky | NSX | H = int(H_hex) mod n, S = H^d mod n | Ky bang Private Key |
| Xac thuc | Thiet bi | H_new = int(hash(firmware)) mod n | Tinh lai ban bam |
| Xac thuc | Thiet bi | H' = S^e mod n | Giai ma chu ky bang Public Key |
| Xac thuc | Thiet bi | Ket luan: H' == H_new ? | So sanh |

**Ly do xac thuc hoat dong dung:**

```
H' = S^e mod n
   = (H^d)^e mod n
   = H^(d x e) mod n
   = H mod n          [vi d x e = 1 (mod phi(n))]
   = H
```

Neu firmware khong bi sua: H_new == H, suy ra H' == H_new.
Neu firmware bi sua: H_new != H (ham bam thay doi hoan toan), suy ra H' != H_new.

---

## Cac moi de doa ma he thong bao ve duoc

| Kich ban tan cong | Bao ve? | Giai thich |
|-------------------|:-------:|------------|
| Ke tan cong sua 1 byte firmware | Co | Ban bam thay doi -> H_new != H' |
| Ke tan cong thay toan bo firmware | Co | Khong co Private Key -> khong tao duoc S hop le |
| Ke tan cong doan chu ky | Co | Khong gian chu ky qua lon (phu thuoc kich thuoc n) |
| Nghe len kenh truyen | Co | Public Key la cong khai -- khong can che giau |
| Tu choi chu ky (Non-repudiation) | Co | Chi Private Key moi tao duoc S hop le |
