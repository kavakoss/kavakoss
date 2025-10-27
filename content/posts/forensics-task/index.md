---
title: "Forensics-Task"
date: 2025-10-27T08:58:37+07:00
draft: false
tableOfContents: true
description: "Ringkasan praktis langkah forensik citra digital di Kali Linux — siap presentasi dan praktik."
categories:
- Digital Forensics
tags:
- Cybercrime
- Image Forensics
- Kali Linux
---

## 🧩 Pendahuluan

Image forensics adalah proses untuk **menganalisis keaslian gambar digital**, mendeteksi **manipulasi**, dan **mengambil bukti tersembunyi** (metadata, data steganografi, file tersembunyi, dll). Semua dilakukan secara **forensically sound** — artinya tidak mengubah bukti asli.

---

## ⚙️ 1. Persiapan Lingkungan

### Jalankan Kali Linux dalam Mode Forensik

```bash
# Boot dari USB Kali → Pilih “Forensic Mode”
```

**Tujuan:** mencegah auto-mount, menonaktifkan swap, dan menjaga integritas bukti.

### Instalasi Tools Penting

```bash
sudo apt update && sudo apt upgrade
sudo apt install autopsy sleuthkit guymager foremost exiftool binwalk steghide testdisk scalpel bulk-extractor
```

🖼️ *Tempat hasil screenshot/CLI output nanti di sini.*

---

## 📥 2. Akuisisi Bukti Digital

### Forensic Imaging (CLI)

```bash
sudo fdisk -l
sudo dd if=/dev/sdb of=/mnt/evidence/disk.dd bs=4M status=progress conv=noerror,sync
```

**Atau GUI (Guymager):** pilih device → *Acquire Image* → pilih format (E01/dd) → aktifkan hash MD5 & SHA256.

### Verifikasi Hash

```bash
md5sum disk.dd > disk.md5
sha256sum disk.dd > disk.sha256
md5sum -c disk.md5
sha256sum -c disk.sha256
```

🖼️ *Tempat hasil hash di sini.*

---

## 🔍 3. Analisis Metadata

### Ekstraksi Metadata dengan ExifTool

```bash
exiftool image.jpg
exiftool -AllDates -GPS* -Software -Model image.jpg
```

**Periksa:** waktu pembuatan, software editing, koordinat GPS, model kamera.

### Analisis Strings

```bash
strings -n 8 image.jpg | grep -i "flag\|secret\|key"
```

🖼️ *Tempat hasil exiftool/strings di sini.*

---

## 🧠 4. Deteksi Manipulasi Gambar

### Error Level Analysis (ELA)

Gunakan situs berikut:

* [FotoForensics](https://fotoforensics.com)
* [Forensically (29a.ch)](https://29a.ch/photo-forensics)

🧩 Bright area = kemungkinan edit baru.

### Clone & Splicing Detection

Gunakan **Clone Detection** di Forensically untuk melihat area yang di-*copy-paste* dalam gambar.

🖼️ *Tempat hasil ELA dan clone detection di sini.*

---

## 🕵️ 5. Deteksi Steganografi

### Binwalk (Embedded File)

```bash
binwalk -Me image.jpg
```

Jika ditemukan file di dalam image → buka folder hasil ekstraksi `_image.jpg.extracted/`.

### Steghide (Hidden Data)

```bash
steghide info image.jpg
steghide extract -sf image.jpg -p ""
```

Jika butuh brute-force password:

```bash
for pass in $(cat wordlist.txt); do steghide extract -sf image.jpg -p "$pass"; done
```

### Zsteg (PNG/BMP)

```bash
zsteg -a image.png
```

🖼️ *Tempat hasil binwalk/steghide di sini.*

---

## 🧱 6. Recovery & File System Forensics

### PhotoRec / Foremost

```bash
sudo photorec disk.dd
sudo foremost -t jpg,png -i disk.dd -o /output/recovery/
```

**Autopsy GUI (opsional):** `sudo autopsy` → buat case baru → import disk image → analisis file dan timeline.

🖼️ *Tempat hasil recovery di sini.*

---

## 📊 7. Dokumentasi & Pelaporan

### Struktur Laporan Forensik

```
Case ID     : 2025-CYBER-001
Analyst     : [Nama Anda]
Date        : [Tanggal]
Evidence    : suspect_image.jpg
Tool Used   : ExifTool, Binwalk, Guymager, Autopsy
Findings    : Manipulasi ditemukan pada region [x,y]
Conclusion  : Image menunjukkan indikasi edit Photoshop.
```

🖼️ *Tempat hasil laporan/screenshot di sini.*

### Template Chain of Custody

| Step | Person       | Date   | Action      | Location      |
| ---- | ------------ | ------ | ----------- | ------------- |
| 1    | Investigator | [date] | Acquisition | Lab 01        |
| 2    | Analyst      | [date] | Imaging     | Evidence Disk |

---

## 🧾 8. Praktik Terbaik (Best Practices)

✅ **Do:**

* Gunakan *forensic mode* dan *write blocker*
* Verifikasi hash di setiap tahap
* Dokumentasikan seluruh langkah (screenshot, timestamp)
* Cross-verify hasil dengan beberapa tools

❌ **Don’t:**

* Analisis langsung pada bukti asli
* Mengubah metadata tanpa mencatat
* Menyimpulkan tanpa bukti kuat

---

## 🧩 Kesimpulan

Dengan langkah-langkah di atas, kamu dapat:

* Mengekstrak metadata penting
* Mendeteksi manipulasi (ELA, clone detection)
* Mencari data tersembunyi (stego, binwalk)
* Melakukan recovery dan pelaporan yang sah di pengadilan