<div align="center">

<img src="docs/chatguard_logo.jpg" alt="ChatGuard Logo" width="150" style="border-radius: 28px;" />

# ChatGuard

**_"Aman dulu sebelum buka—deteksi file berbahaya secara pintar sebelum diunduh."_**

[![Version](https://img.shields.io/badge/version-v1.2.0-blue.svg)](../../releases/tag/v1.2.0)
[![Platform](https://img.shields.io/badge/platform-Android%208.0%2B-3DDC84.svg?logo=android&logoColor=white)](android/)
[![Backend](https://img.shields.io/badge/API-FastAPI%20%2B%20SQLite-009688.svg?logo=fastapi&logoColor=white)](api/)
[![Privacy](https://img.shields.io/badge/privacy-100%25%20Local%20First-16A34A.svg)](docs/privacy-policy.html)

[Download APK (v1.2.0)](../../releases/latest) • [Kebijakan Privasi](docs/privacy-policy.html) • [Arsitektur](#-cara-kerja-chatguard) • [Build Lokal](#-panduan-build-lokal)

</div>

---

## Kenapa ChatGuard?

Modus penipuan lewat WhatsApp dan Telegram (*undangan pernikahan `.apk`*, *resi kurir palsu*, *surat tilang PDF berbahaya*) sering menjebak korban karena **file langsung terunduh atau terbuka** sebelum pengguna sempat curiga.

**ChatGuard** memberi peringatan **sebelum file diunduh** langsung di atas layar chat, lengkap dengan penjelasan bahasa awam dan sinyal teknisnya.

---

## Alur Deteksi (Interaktif)

```mermaid
flowchart LR
    A["💬 Pesan / File di WhatsApp & Telegram"] --> B{"🛡️ Mode Aman ON?"}
    B -- "OFF" --> Z["Dijeda"]
    B -- "ON" --> C["Stage 1: Notifikasi & Layar Chat"]
    C --> D{"Terindikasi Berisiko?"}
    D -- "Ya" --> E["🚨 Pop-up Overlay Peringatan\n(Alasan • Dampak • Saran • Sinyal Teknis)"]
    E --> F{"Pilih Aksi"}
    F -- "Ya, Blokir & Hapus" --> G["🚫 Masuk Daftar Blokir Lokal\n+ Hapus Salinan Unduhan"]
    F -- "Tidak" --> H["📝 Tercatat di Log Aktivitas"]
    A -. "Jika diunduh / di-Share" .-> I["Stage 2: Inspeksi Isi File\n(Magic Bytes • APK • PDF • Office • ZIP)"]
    I --> H
```

---

## Fitur Utama

<details open>
<summary><b>🛡️ 1. Mode Aman ON/OFF & Walkthrough Awal</b></summary>

- **Sakelar Mode Aman** langsung di Beranda untuk mengaktifkan atau menjeda pemantauan kapan saja.
- **Walkthrough interaktif 4 langkah** saat pertama kali membuka aplikasi, plus **Persetujuan Privasi** yang jelas.

</details>

<details>
<summary><b>💬 2. Deteksi Pra-Unduh (Notifikasi & Layar Chat)</b></summary>

- **Akses Notifikasi (`NotificationListenerService`):** Mendeteksi ekstensi ganda (`.pdf.apk`), skrip berbahaya (`.exe`, `.bat`, `.vbs`, `.js`), dan kata pancingan (*undangan, resi, tilang, tagihan, kurir, paket*).
- **Pantau Layar Chat (`AccessibilityService`, opsional):** Membaca nama dokumen yang tampil langsung di layar WhatsApp/Telegram tanpa menunggu notifikasi atau mengunduh file.
- **Anti-Spam *Scroll*:** *Cooldown* pintar **10 menit** per file agar pop-up tidak muncul berulang saat menggulir chat.

</details>

<details>
<summary><b>🚨 3. Pop-up Overlay Lengkap + Blokir & Hapus</b></summary>

- Menampilkan **Apa yang ditemukan**, **Dampak jika dibuka**, **Saran aman**, dan **Sinyal Teknis** (`LURE_KEYWORDS_ID`, `DOUBLE_EXTENSION_APK`, dll.).
- Tombol **`Ya, Blokir & Hapus`** menandai file ke daftar blokir lokal dan menghapus salinan fisik jika sudah terunduh di `Download` / `WhatsApp Documents`.

</details>

<details>
<summary><b>📚 4. Dashboard Log Aktivitas & Belajar Ancaman</b></summary>

- Statistik lokal (**Terdeteksi**, **Diblokir**, **Pola Lokal**).
- Setiap kartu aktivitas menampilkan **💡 Pelajaran untuk Anda** agar pengguna umum makin mengenali pola penipuan terbaru.

</details>

<details>
<summary><b>🔍 5. Inspeksi Isi File Lokal (Stage 2) & Mode Hybrid Opsional</b></summary>

- Memeriksa **Magic Bytes** (mendeteksi APK/ZIP yang menyamar jadi `.pdf`), izin berisiko di `AndroidManifest.xml`, `/JavaScript` & `/OpenAction` di PDF, macro Office, serta arsip ZIP/RAR.
- Dapat dihubungkan ke server **Hybrid Reputation API** (`api/`) secara opsional (hanya mengirim hash SHA-256 & metadata anonim).

</details>

---

## Komitmen Privasi

| Aspek | Status di ChatGuard |
| :--- | :--- |
| Akses Kontak, Galeri/Foto, Lokasi | **Tidak pernah diminta** |
| Menyimpan atau mengirim isi pesan chat | **Tidak pernah dilakukan** |
| Mengunggah isi dokumen pribadi | **Tidak pernah dilakukan** |
| Deteksi & pembelajaran pola ancaman | **100% lokal di perangkat** |

---

## Panduan Build Lokal

<details>
<summary><b>📱 Build Aplikasi Android (JDK 17 + Android SDK)</b></summary>

```powershell
cd android
.\gradlew.bat :app:testDebugUnitTest :app:assembleRelease
```
Output APK rilis: `android/app/build/outputs/apk/release/app-release.apk`

</details>

<details>
<summary><b>🌐 Jalankan Hybrid Reputation API (Opsional)</b></summary>

```powershell
cd api
pytest tests -v
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

</details>
