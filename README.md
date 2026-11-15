# ChatGuard

> *"Aman dulu sebelum buka—deteksi file berbahaya secara pintar sebelum diunduh."*

**ChatGuard** adalah aplikasi pelindung file phishing untuk Android (WhatsApp & Telegram) beserta layanan **Hybrid Reputation API** opsional yang dapat dijalankan sendiri (*self-hosted*).

## Fitur Utama

- **Mode Aman ON/OFF:** Aktifkan atau jeda perlindungan kapan saja langsung dari Beranda.
- **Deteksi Pra-Unduh (Stage 1):**
  - **Akses Notifikasi (`NotificationListenerService`):** Mendeteksi ekstensi ganda (`.pdf.apk`), file eksekusi berbahaya, dan kata pancingan penipuan (*undangan, resi, tilang, tagihan, kurir, paket*) pada notifikasi masuk.
  - **Pantau Layar Chat (`AccessibilityService`, opsional):** Mendeteksi nama file mencurigakan yang tampil di layar WhatsApp/Telegram tanpa menunggu notifikasi atau mengunduh file, dilengkapi *cooldown* 10 menit anti-spam *scroll*.
  - **Pop-up Overlay Lengkap:** Menampilkan *Apa yang ditemukan, Dampak, Saran, Sinyal Teknis*, serta tombol **`Ya, Blokir & Hapus`** / **`Tidak`**.
- **Inspeksi Isi File Lokal (Stage 2):**
  - Memeriksa *magic bytes* / header file asli, izin berbahaya pada `.apk`, `/JavaScript` & `/OpenAction` pada `.pdf`, macro pada dokumen Office, serta isi arsip `.zip`/`.rar`.
- **Dashboard Log Aktivitas & Belajar Ancaman:**
  - Mencatat riwayat deteksi dan menampilkan pelajaran singkat agar pengguna umum dapat mengenali modus penipuan.
- **Privasi 100% Lokal:**
  - Tidak mengakses daftar kontak, foto/galeri pribadi, lokasi, maupun menyimpan/mengirim isi percakapan chat.

## Struktur Proyek

- `android/` — Aplikasi Android (Kotlin, Jetpack Compose, Room, OkHttp)
- `api/` — Hybrid Reputation API (Python, FastAPI, SQLite)
- `docs/privacy-policy.html` — Halaman kebijakan privasi siap *hosting*

## Menjalankan & Build Lokal

### Android
```powershell
cd android
.\gradlew.bat :app:testDebugUnitTest :app:assembleRelease
```

### Hybrid Reputation API (Opsional)
```powershell
cd api
pytest tests -v
uvicorn app.main:app --host 0.0.0.0 --port 8000
```
