# AV-01 — Compromised Administration Workstation (FINAL LMS)

Lingkungan: Windows 11, ESET Internet Security dari langganan ESET HOME Security Essential, PowerShell 5.1.

## Alur deployment
1. Snapshot VM Windows 11; jalankan PowerShell Administrator pada folder paket.
2. `Set-ExecutionPolicy -Scope Process Bypass -Force`
3. `.\setup.ps1 -Action Install`
4. Instal ESET resmi dan aktifkan lisensi; lakukan update modul perlindungan. Pastikan Windows Security tidak memiliki produk yang saling bertabrakan.
5. `.\setup.ps1 -Action Preflight`; konfirmasi di GUI ESET real-time/HIPS/Webcam/Web tersedia. Untuk uji pemblokiran nyata, OBS Virtual Camera perlu terdaftar dan diakses aplikasi uji; log simulasi tetap tersedia sebagai latihan cadangan.
6. Snapshot pre-trigger; dengan izin instruktur jalankan `.\setup.ps1 -Action RunScenario -ConfirmTest`.
7. Untuk membuka panduan interaktif, gunakan per modul: `.\setup.ps1 -Action Trigger -Module Webcam -ConfirmTest -LaunchInteractiveTests` dan `.\setup.ps1 -Action Trigger -Module Web -ConfirmTest -LaunchInteractiveTests`.
8. Investigasi di ESET (log, scan, webcam, web) dan `C:\CTF-Lab-AV01\Evidence`; jalankan `.\setup.ps1 -Action Verify`.
9. Kerjakan 15 pilihan ganda serta submit 5 flag ke LMS. Jangan menjalankan `CheckAnswer/SubmitFlag` karena penilaian dilayani oleh LMS.

## Lima batas pengujian
- EICAR adalah file uji antivirus yang dikenal industri. File bisa diblokir sebelum tersimpan. File hilang **bukan** bukti karantina.
- `RunScenario` hanya memicu file EICAR pada Malware dan Scan, menjalankan aktivitas benign HIPS, serta menyiapkan rencana webcam/web. Modul webcam kini juga menghasilkan log SYNTHETIC_CTF; hal ini **bukan** bukti lima fungsi ESET telah memblokir.
- Untuk HIPS: instruktur membuat aturan khusus untuk marker latihan dan membuktikannya dengan hasil nyata. Jangan menggunakan kebijakan luas yang membatasi aplikasi sah.
- Untuk webcam: OBS Virtual Camera sebagai perangkat virtual bisa digunakan apabila dikenali ESET, tetapi harus dicoba dari aplikasi klien; fallback CSV/log berlabel SYNTHETIC_CTF hanya untuk kemampuan analisis.
- Untuk web: gunakan mekanisme pengujian resmi AMTSO yang didukung; hasil ESET dan browser harus sesuai.

Tidak ada kunci LMS atau token flag tersimpan dalam paket peserta. Kunci diberikan terpisah untuk instruktur. Jangan gunakan mesin produksi.

## Revisi OBS Webcam / Backup Log (2026-10-22)
- Jalankan OBS > Start Virtual Camera; lalu ESET Webcam Protection harus aktif.
- `\.setup.ps1 -Action Preflight`: inventaris OBS Virtual Camera dan service ESET.
- `\.setup.ps1 -Action Trigger -Module Webcam -ConfirmTest`: menghasilkan `C:\CTF-Lab-AV01\Webcam\webcam_access_training.csv` dan `.log`. **Tidak mengakses webcam, tidak membuat log ESET.**
- `\.setup.ps1 -Action RunScenario -ConfirmTest`: menjalankan seluruh modul termasuk membuat log webcam dummy.
- Jika OBS kompatibel, buka aplikasi kamera tepercaya, pilih OBS Virtual Camera, atur ESET Webcam Protection untuk Block, lalu buktikan tidak ada stream dan dokumentasikan aturan ESET.
- Jika OBS tidak terdeteksi, gunakan CSV untuk latihan analisis saja. Nilai flag webcam di LMS sebaiknya ditandai evidence simulasi/tidak memenuhi uji SOW.
