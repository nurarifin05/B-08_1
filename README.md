# AV-01 — Compromised Administration Workstation (FINAL LMS)

Lingkungan: Windows 11, ESET Internet Security dari langganan ESET HOME Security Essential, PowerShell 5.1.

## Alur deployment
1. Snapshot VM Windows 11; jalankan PowerShell Administrator pada folder paket.
2. `Set-ExecutionPolicy -Scope Process Bypass -Force`
3. `.\setup.ps1 -Action Install`
4. Instal ESET resmi dan aktifkan lisensi; lakukan update modul perlindungan. Pastikan Windows Security tidak memiliki produk yang saling bertabrakan.
5. `.\setup.ps1 -Action Preflight`; konfirmasi di GUI ESET real-time/HIPS/Webcam/Web tersedia. Webcam memerlukan perangkat kamera yang benar-benar terpasang.
6. Snapshot pre-trigger; dengan izin instruktur jalankan `.\setup.ps1 -Action RunScenario -ConfirmTest`.
7. Untuk membuka panduan interaktif, gunakan per modul: `.\setup.ps1 -Action Trigger -Module Webcam -ConfirmTest -LaunchInteractiveTests` dan `.\setup.ps1 -Action Trigger -Module Web -ConfirmTest -LaunchInteractiveTests`.
8. Investigasi di ESET (log, scan, webcam, web) dan `C:\CTF-Lab-AV01\Evidence`; jalankan `.\setup.ps1 -Action Verify`.
9. Kerjakan 15 pilihan ganda serta submit 5 flag ke LMS. Jangan menjalankan `CheckAnswer/SubmitFlag` karena penilaian dilayani oleh LMS.

## Lima batas pengujian
- EICAR adalah file uji antivirus yang dikenal industri. File bisa diblokir sebelum tersimpan. File hilang **bukan** bukti karantina.
- `RunScenario` hanya memicu file EICAR pada Malware dan Scan, menjalankan aktivitas benign HIPS, serta menyiapkan rencana webcam/web. Ini **bukan** bukti lima fungsi ESET telah memblokir.
- Untuk HIPS: instruktur membuat aturan khusus untuk marker latihan dan membuktikannya dengan hasil nyata. Jangan menggunakan kebijakan luas yang membatasi aplikasi sah.
- Untuk webcam: perlu hardware kamera dan aplikasi uji yang disetujui; aplikasi Camera resmi harus tetap bisa dipakai.
- Untuk web: gunakan mekanisme pengujian resmi AMTSO yang didukung; hasil ESET dan browser harus sesuai.

Tidak ada kunci LMS atau token flag tersimpan dalam paket peserta. Kunci diberikan terpisah untuk instruktur. Jangan gunakan mesin produksi.
