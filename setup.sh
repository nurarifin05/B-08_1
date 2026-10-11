#!/bin/bash
# ==============================================================================
# Script Generator Lab CTF: VM 1 - Suspicious Web Activity (Ubuntu 24.04)
# ==============================================================================

set -e

echo "[*] Menginisialisasi pembuatan direktori artefak..."
mkdir -p /var/log/nginx
mkdir -p /srv/lab/uploads
mkdir -p /var/log/edr

# 1. Membuat file Artefak Kasus (Simulasi Upload)
ARTIFACT_PATH="/srv/lab/uploads/report.php.txt"
cat << 'EOF' > "$ARTIFACT_PATH"
<?php
/* 
 * CTF LAB ARTIFACT - FOR INVESTIGATION PURPOSES ONLY
 * Created by: www-data
 * Purpose: Simulated file upload payload testing
 * Status: Non-executable plain text extension (.txt)
 * FLAG: FLAG{UBU01_WEB_ARTIFACT_58291A}
 */
echo "Report generated successfully at " . date('Y-m-d H:i:s');
?>
EOF

# Atur kepemilikan dan hak akses file
chown -R www-data:www-data /srv/lab
chmod 644 "$ARTIFACT_PATH"

# Hitung hash SHA-256 secara dinamis dari file artefak
FILE_SHA256=$(sha256sum "$ARTIFACT_PATH" | awk '{print $1}')

echo "[*] Hash SHA-256 dari artefak: $FILE_SHA256"

# 2. Membuat Nginx Access Log (/var/log/nginx/access.log)
cat << 'EOF' > /var/log/nginx/access.log
192.168.10.15 - - [09/Oct/2026:14:10:05 +0000] "GET /index.php HTTP/1.1" 200 4523 "http://192.168.10.1/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
192.168.10.20 - - [09/Oct/2026:14:12:18 +0000] "GET /static/style.css HTTP/1.1" 200 1250 "http://192.168.10.1/index.php" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
10.14.7.88 - - [09/Oct/2026:14:20:01 +0000] "GET /admin HTTP/1.1" 404 162 "-" "CyberTool/2.1 Scanner"
10.14.7.88 - - [09/Oct/2026:14:20:05 +0000] "GET /phpmyadmin HTTP/1.1" 404 162 "-" "CyberTool/2.1 Scanner"
10.14.7.88 - - [09/Oct/2026:14:20:12 +0000] "GET /index.php?page=../../../../etc/passwd HTTP/1.1" 400 280 "-" "CyberTool/2.1 Scanner"
10.14.7.88 - - [09/Oct/2026:14:22:10 +0000] "POST /upload.php HTTP/1.1" 200 142 "-" "CyberTool/2.1 Scanner"
10.14.7.88 - - [09/Oct/2026:14:23:05 +0000] "GET /uploads/report.php.txt HTTP/1.1" 200 238 "-" "CyberTool/2.1 Scanner"
192.168.10.15 - - [09/Oct/2026:14:24:00 +0000] "GET /dashboard.php HTTP/1.1" 200 3120 "http://192.168.10.1/index.php" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
EOF

# 3. Membuat Nginx Error Log (/var/log/nginx/error.log)
cat << 'EOF' > /var/log/nginx/error.log
2026/10/09 14:10:05 [notice] 1420#1420: *1 using inherited sockets from "6;7;"
2026/10/09 14:20:12 [error] 1432#1432: *3 FastCGI sent in stderr: "PHP message: PHP Warning:  file_get_contents(../../../../etc/passwd): Failed to open stream: Permission denied in /var/www/html/index.php on line 42" while reading response header from upstream, client: 10.14.7.88, server: localhost, request: "GET /index.php?page=../../../../etc/passwd HTTP/1.1", host: "10.0.2.15"
2026/10/09 14:22:10 [notice] 1580#1580: *4 [php-fpm] File upload processed: original_name="report.php.txt", destination="/srv/lab/uploads/report.php.txt", client_ip="10.14.7.88"
EOF

# 4. Membuat EDR Alert Log (/var/log/edr/alerts.log)
cat << EOF > /var/log/edr/alerts.log
{"timestamp": "2026-10-09T14:22:11Z", "event_id": 11, "event_type": "file_creation", "file_path": "/srv/lab/uploads/report.php.txt", "user": "www-data", "process_name": "php-fpm8.3", "pid": 1580, "sha256": "$FILE_SHA256", "severity": "MEDIUM", "rule_description": "New file created in web directory by webserver process"}
EOF

# 5. Membuat Case Notes (/srv/lab/case_notes.txt)
cat << 'EOF' > /srv/lab/case_notes.txt
===============================================================================
CASE NOTES - INCIDENT #2026-1009-WEB
===============================================================================
Deskripsi Kasus:
Pada tanggal 9 Oktober 2026 pukul 14:25:00 UTC, Tim SOC menerima peringatan dari 
sensor EDR mengenai pembuatan file baru di direktori aplikasi web internal (/srv/lab/uploads/).
Pada jendela waktu yang sama, terdeteksi lonjakan lalu lintas HTTP yang tidak lazim.

Infrastruktur Terkait:
- Subnet Internal Legitimate: 192.168.10.0/24
- Server Name: web-app-train-01 (Ubuntu 24.04 LTS)
- Web Server Log: /var/log/nginx/access.log & /var/log/nginx/error.log
- EDR Log: /var/log/edr/alerts.log

Tugas Analis:
Lakukan investigasi forensik pada artefak yang tersedia untuk menjawab pertanyaan insiden.
===============================================================================
EOF

# Mengatur izin baca seluruh artefak latihan agar dapat diakses pengguna non-root
chmod 644 /var/log/nginx/*.log
chmod 644 /var/log/edr/alerts.log
chmod 644 /srv/lab/case_notes.txt

echo "[+] Setup Lab Skenario 1 Berhasil!"
echo "[+] Artefak siap dianalisis di /var/log/nginx/, /var/log/edr/, dan /srv/lab/"
