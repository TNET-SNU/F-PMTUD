#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <pthread.h>
#include <fcntl.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <sys/time.h>

#define BUFFER_SIZE 65535
#define MAGIC_MARKER "FPMT"   // 4바이트 식별자
#define EXIT_MARKER  "FEXIT"  // 종료 요청 식별자
#define IP_HDR_SIZE  20       // 일반적인 IPv4 헤더 길이 (옵션 없음)
#define UDP_HDR_SIZE 8        // UDP 헤더 길이

// ---------------------------------------------------
// ICMP 관련 전역
// ---------------------------------------------------
typedef struct {
    int probe_size;          // ICMP 수신 시점에 전송했던 패킷의 전체 크기
    uint16_t next_hop_mtu;   // ICMP 'fragmentation needed' 메시지의 next-hop MTU
} icmp_info_t;

#define MAX_ICMP_PACKETS 20
static icmp_info_t icmp_info[MAX_ICMP_PACKETS];
static int icmp_count = 0;

// ICMP 스레드 제어 플래그
static volatile int collecting = 1;

// mutex
static pthread_mutex_t icmp_mutex  = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t probe_mutex = PTHREAD_MUTEX_INITIALIZER;

// 현재 보내는 패킷의 크기 (ICMP 스레드에서 참조)
static volatile int current_probe_size = 0;

// 전역 성공/실패 플래그
static int overall_success = 0;

// ---------------------------------------------------
// 여러 패킷 테스트 결과를 저장할 배열
// ---------------------------------------------------
#define MAX_TESTS 20  // 2 MTU 설정 x 6 추가 테스트 + 기타
static int test_sizes[MAX_TESTS];
static int test_results[MAX_TESTS];   // 성공 시 서버 응답
static int test_success[MAX_TESTS];   // 1=성공, 0=실패
static int test_count = 0;            // 실제 사용한 테스트 개수

// ---------------------------------------------------
// Usage 출력
// ---------------------------------------------------
static void print_usage(const char *prog_name) {
    fprintf(stderr, "Usage: %s -i <Destination IP> [-p <Destination Port>] [-P <Prober Port>]\n",
            prog_name);
}

// ---------------------------------------------------
// 로컬 IP 가져오기 (connect + getsockname)
// ---------------------------------------------------
static int get_local_ip(char *local_ip, size_t len, const char *server_ip, int server_port) {
    int sock;
    struct sockaddr_in serv;
    struct sockaddr_in local;
    socklen_t local_len = sizeof(local);

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket()");
        return -1;
    }
    memset(&serv, 0, sizeof(serv));
    serv.sin_family = AF_INET;
    serv.sin_port   = htons(server_port);

    if (inet_pton(AF_INET, server_ip, &serv.sin_addr) <= 0) {
        perror("inet_pton()");
        close(sock);
        return -1;
    }
    if (connect(sock, (struct sockaddr *)&serv, sizeof(serv)) < 0) {
        perror("connect()");
        close(sock);
        return -1;
    }
    if (getsockname(sock, (struct sockaddr *)&local, &local_len) < 0) {
        perror("getsockname()");
        close(sock);
        return -1;
    }
    inet_ntop(AF_INET, &local.sin_addr, local_ip, len);

    close(sock);
    return 0;
}

// ---------------------------------------------------
// 로컬 IP가 할당된 인터페이스의 MTU 얻기
// ---------------------------------------------------
static int get_interface_mtu(const char *local_ip) {
    struct ifaddrs *ifaddr, *ifa;
    int mtu = -1;
    int sockfd;
    struct ifreq ifr;
    char addr[INET_ADDRSTRLEN];

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return -1;
    }
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        freeifaddrs(ifaddr);
        return -1;
    }
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;
        if (ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
            inet_ntop(AF_INET, &sa->sin_addr, addr, sizeof(addr));
            if (strcmp(addr, local_ip) == 0) {
                memset(&ifr, 0, sizeof(ifr));
                strncpy(ifr.ifr_name, ifa->ifa_name, IFNAMSIZ - 1);
                if (ioctl(sockfd, SIOCGIFMTU, &ifr) == -1) {
                    perror("ioctl(SIOCGIFMTU)");
                } else {
                    mtu = ifr.ifr_mtu;
                }
                break;
            }
        }
    }
    freeifaddrs(ifaddr);
    close(sockfd);
    return mtu;
}

// ---------------------------------------------------
// "lo" 제외, 첫 번째 IPv4 인터페이스 이름 얻기
// ---------------------------------------------------
static int get_first_nonlo_interface(char *if_name_out, size_t size) {
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) != 0) {
        perror("getifaddrs");
        return -1;
    }
    int found = 0;
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_name || !ifa->ifa_addr)
            continue;
        if (ifa->ifa_addr->sa_family == AF_INET) {
            if (strcmp(ifa->ifa_name, "lo") != 0) {
                strncpy(if_name_out, ifa->ifa_name, size - 1);
                if_name_out[size - 1] = '\0';
                found = 1;
                break;
            }
        }
    }
    freeifaddrs(ifaddr);
    if (!found) {
        return -1;
    }
    return 0;
}

// ---------------------------------------------------
// system() 호출로 인터페이스 MTU 설정
// ---------------------------------------------------
static int try_set_mtu(const char *ifname, int mtu_val) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "sudo ip link set dev %s mtu %d 2>&1", ifname, mtu_val);

    FILE *fp = popen(cmd, "r");
    if (!fp) {
        fprintf(stderr, "Failed to run command: %s\n", cmd);
        return -1;
    }
    int success = 1;
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "Error: mtu greater than device maximum.") ||
            strstr(line, "mtu") == NULL && strstr(line, "Error") != NULL) {
            success = 0;
        }
    }
    pclose(fp);
    return success ? 0 : -1;
}

// ---------------------------------------------------
// ICMP 수신 스레드 (frag needed / time exceeded)
// ---------------------------------------------------
static void *icmp_collector(void *arg) {
    int icmp_sock = *(int *)arg;
    unsigned char recv_buf[BUFFER_SIZE];

    while (collecting) {
        ssize_t len = recv(icmp_sock, recv_buf, sizeof(recv_buf), 0);
        if (len < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                usleep(10000);
                continue;
            } else {
                perror("recv() from icmp raw socket");
                break;
            }
        }
        if (len < (ssize_t)(sizeof(struct iphdr) + sizeof(struct icmphdr)))
            continue;

        struct iphdr *ip_hdr = (struct iphdr *)recv_buf;
        unsigned int ip_header_len = ip_hdr->ihl << 2;
        if (len < ip_header_len + sizeof(struct icmphdr))
            continue;

        struct icmphdr *icmp_hdr = (struct icmphdr *)(recv_buf + ip_header_len);

        int probe_size_snapshot = 0;
        pthread_mutex_lock(&probe_mutex);
        probe_size_snapshot = current_probe_size;
        pthread_mutex_unlock(&probe_mutex);

        // frag needed
        if (icmp_hdr->type == ICMP_DEST_UNREACH && icmp_hdr->code == 4) {
            if (len < ip_header_len + sizeof(struct icmphdr) + sizeof(uint16_t))
                continue; // next_hop_mtu 정보 부족
            uint16_t next_hop_mtu = ntohs(*(uint16_t *)((unsigned char *)icmp_hdr + 6));
            pthread_mutex_lock(&icmp_mutex);
            if (icmp_count < MAX_ICMP_PACKETS) {
                icmp_info[icmp_count].probe_size   = probe_size_snapshot;
                icmp_info[icmp_count].next_hop_mtu = next_hop_mtu;
                icmp_count++;
            }
            pthread_mutex_unlock(&icmp_mutex);
        }
        // time exceeded
        else if (icmp_hdr->type == ICMP_TIME_EXCEEDED) {
            pthread_mutex_lock(&icmp_mutex);
            if (icmp_count < MAX_ICMP_PACKETS) {
                icmp_info[icmp_count].probe_size   = probe_size_snapshot;
                icmp_info[icmp_count].next_hop_mtu = (uint16_t)probe_size_snapshot;
                icmp_count++;
            }
            pthread_mutex_unlock(&icmp_mutex);
        }
    }
    return NULL;
}

// ---------------------------------------------------
// Step(B)에서 패킷 전송 후 결과 기록
// ---------------------------------------------------
static void send_and_record_test(int sock,
                                 const struct sockaddr_in *dest_addr,
                                 int test_size,
                                 int idx,
                                 const char *info_label,
                                 const char *if_name)
{
    if (test_count >= MAX_TESTS) {
        fprintf(stderr, "[mtud_prober] Maximum number of tests reached. Skipping test size %d.\n", test_size);
        return;
    }

    test_sizes[test_count]   = test_size;
    test_results[test_count] = -1;
    test_success[test_count] = 0;

    int payload_len = test_size - IP_HDR_SIZE - UDP_HDR_SIZE;
    if (payload_len < 4) {
        fprintf(stderr,
                "[mtud_prober] %s: packet size %d is too small (cannot contain IP/UDP header+marker)\n",
                info_label, test_size);
        test_count++;
        return;
    }
    char *buf = (char *)calloc(1, payload_len);
    if (!buf) {
        perror("[mtud_prober] calloc in send_and_record_test");
        test_count++;
        return;
    }
    memcpy(buf, MAGIC_MARKER, 4);

    int attempts     = 0;
    int got_response = 0;
    while (attempts < 3 && !got_response) {
        attempts++;
        // 현재 전송 크기를 global로 설정 (ICMP 스레드가 참조)
        pthread_mutex_lock(&probe_mutex);
        current_probe_size = test_size;
        pthread_mutex_unlock(&probe_mutex);

        ssize_t sent = sendto(sock, buf, payload_len, 0,
                              (struct sockaddr *)dest_addr, sizeof(*dest_addr));
        if (sent < 0) {
            perror("[mtud_prober] sendto() in send_and_record_test");
            break;
        }
        fprintf(stderr,
                "[mtud_prober] %s: sent UDP %zd bytes (total test size %d) to %s:%u (attempt %d)\n",
                info_label, sent + UDP_HDR_SIZE, test_size,
                inet_ntoa(dest_addr->sin_addr), ntohs(dest_addr->sin_port),
                attempts);

        // 4바이트 응답 수신
        char response[sizeof(int)];
        ssize_t ret_recv = recv(sock, response, sizeof(response), 0);
        if (ret_recv == (ssize_t)sizeof(response)) {
            int server_result = ntohl(*(int *)response);
            got_response      = 1;
            overall_success   = 1;
            test_success[test_count] = 1;
            test_results[test_count] = server_result;

            fprintf(stderr,
                    "Probe packet size: %d bytes, Maximum fragment size: %d bytes\n",
                    test_size, server_result);
        } else if (ret_recv < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            fprintf(stderr,
                    "[mtud_prober] %s: no response from server (attempt %d)\n",
                    info_label, attempts);
        } else if (ret_recv < 0) {
            perror("[mtud_prober] recv error in send_and_record_test");
        }
    }
    if (!got_response) {
        fprintf(stderr,
                "Probe packet size: %d bytes, F-PMTUD failed\n",
                test_size);
    }
    free(buf);
    test_count++;
}

// ---------------------------------------------------
// main()
// ---------------------------------------------------
int main(int argc, char *argv[]) {
    char *server_ip  = NULL;
    int server_port  = 9999;
    int client_port  = 0;
    int opt;

    while ((opt = getopt(argc, argv, "i:p:P:")) != -1) {
        switch (opt) {
            case 'i':
                server_ip = strdup(optarg);
                break;
            case 'p':
                server_port = atoi(optarg);
                break;
            case 'P':
                client_port = atoi(optarg);
                break;
            default:
                print_usage(argv[0]);
                exit(EXIT_FAILURE);
        }
    }
    if (!server_ip) {
        print_usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, server_ip, &dest_addr.sin_addr) <= 0) {
        fprintf(stderr, "Invalid destination IP address: %s\n", server_ip);
        exit(EXIT_FAILURE);
    }
    dest_addr.sin_port = htons(server_port);

    // pick interface
    char if_name[IFNAMSIZ] = {0};
    if (get_first_nonlo_interface(if_name, sizeof(if_name)) < 0) {
        fprintf(stderr, "[mtud_prober] Could not find any non-lo interface. Exiting.\n");
        exit(EXIT_FAILURE);
    }
    fprintf(stderr, "[mtud_prober] Picked interface: %s\n", if_name);

    // set interface mtu (64000->9000->1500->500 fallback)
    int tries_initial[3]       = {64000, 9000, 1500};
    int configured_mtu_initial  = 500;
    int set_ok_initial          = 0;
    for (int i = 0; i < 3; i++) {
        if (try_set_mtu(if_name, tries_initial[i]) == 0) {
            configured_mtu_initial = tries_initial[i];
            set_ok_initial = 1;
            fprintf(stderr, "[mtud_prober] Successfully set %s MTU to %d\n", if_name, configured_mtu_initial);
            break;
        } else {
            fprintf(stderr, "[mtud_prober] Failed to set %s MTU to %d\n", if_name, tries_initial[i]);
        }
    }
    if (!set_ok_initial) {
        configured_mtu_initial = 500;
        fprintf(stderr, "[mtud_prober] Could not set %s MTU to 1500 either. Fallback to 500.\n", if_name);
    }

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket(AF_INET, SOCK_DGRAM)");
        exit(EXIT_FAILURE);
    }

    if (client_port > 0) {
        struct sockaddr_in client_addr;
        memset(&client_addr, 0, sizeof(client_addr));
        client_addr.sin_family      = AF_INET;
        client_addr.sin_addr.s_addr = INADDR_ANY;
        client_addr.sin_port        = htons(client_port);

        if (bind(sock, (struct sockaddr *)&client_addr, sizeof(client_addr)) < 0) {
            perror("bind() failed for prober port");
            close(sock);
            exit(EXIT_FAILURE);
        } else {
            fprintf(stderr, "[mtud_prober] Bound prober socket to port %d\n", client_port);
        }
    }

    // ICMP
    int icmp_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (icmp_sock < 0) {
        perror("[mtud_prober] ICMP raw socket creation failed");
    } else {
        int flags = fcntl(icmp_sock, F_GETFL, 0);
        fcntl(icmp_sock, F_SETFL, flags | O_NONBLOCK);
    }
    pthread_t icmp_thread;
    if (icmp_sock >= 0) {
        if (pthread_create(&icmp_thread, NULL, icmp_collector, &icmp_sock) != 0) {
            perror("[mtud_prober] pthread_create(icmp_collector) failed");
        }
    }

    // DF=1, TTL=2
    int val = IP_PMTUDISC_DO;
    if (setsockopt(sock, IPPROTO_IP, IP_MTU_DISCOVER, &val, sizeof(val)) < 0) {
        perror("setsockopt(IP_MTU_DISCOVER, IP_PMTUDISC_DO)");
    }
    int ttl = 2;
    if (setsockopt(sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0) {
        perror("setsockopt(IP_TTL)");
    }

    // timeout=1s
    struct timeval timeout;
    timeout.tv_sec  = 1;
    timeout.tv_usec = 0;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("setsockopt(SO_RCVTIMEO)");
    }

    // local IP
    char local_ip[INET_ADDRSTRLEN] = {0};
    if (get_local_ip(local_ip, sizeof(local_ip), server_ip, server_port) != 0) {
        strncpy(local_ip, "Unknown", sizeof(local_ip));
    }
    int local_mtu = get_interface_mtu(local_ip);
    if (local_mtu <= 0) {
        local_mtu = 1500;
    }
    fprintf(stderr, "[mtud_prober] Local IP: %s, Picked Interface: %s, Local MTU: %d\n",
            local_ip, if_name, local_mtu);

    // ----------------------------------------
    // (A) DF=1, TTL=2: 64000->9000->1500 degrade
    // ----------------------------------------
    int final_mtu = configured_mtu_initial;
    int found_icmp = 0;
    int tries_idx  = 0;
    if      (configured_mtu_initial == 64000) tries_idx = 0;
    else if (configured_mtu_initial == 9000)  tries_idx = 1;
    else if (configured_mtu_initial == 1500)  tries_idx = 2;
    else {
        // fallback=500 -> skip
        tries_idx = 3;
    }

    for (; tries_idx < 3; tries_idx++) {
        final_mtu = tries_initial[tries_idx];
        fprintf(stderr, "[mtud_prober] Step(A): Sending packet with size=%d (DF=1, TTL=2)\n", final_mtu);

        int no_icmp_this_step = 1;
        int udp_payload_len = final_mtu - IP_HDR_SIZE - UDP_HDR_SIZE;
        if (udp_payload_len < 4) {
            fprintf(stderr,
                    "[mtud_prober] Packet size %d is too small to contain IP/UDP header + marker.\n",
                    final_mtu);
        } else {
            char *send_buf = (char *)calloc(1, udp_payload_len);
            if (!send_buf) {
                perror("[mtud_prober] calloc for send_buf");
                exit(EXIT_FAILURE);
            }
            memcpy(send_buf, MAGIC_MARKER, 4);

            for (int attempt = 1; attempt <= 3; attempt++) {
                pthread_mutex_lock(&probe_mutex);
                current_probe_size = final_mtu;
                pthread_mutex_unlock(&probe_mutex);

                ssize_t sent_bytes = sendto(sock, send_buf, udp_payload_len, 0,
                                            (struct sockaddr *)&dest_addr, sizeof(dest_addr));
                if (sent_bytes < 0) {
                    perror("[mtud_prober] sendto() in Step(A)");
                } else {
                    fprintf(stderr,
                            "[mtud_prober] Step(A) sent UDP %zd bytes -> total test pkt size %d (attempt %d)\n",
                            sent_bytes + UDP_HDR_SIZE, final_mtu, attempt);
                }
                sleep(1);

                // check icmp
                pthread_mutex_lock(&icmp_mutex);
                for (int k = 0; k < icmp_count; k++) {
                    if (icmp_info[k].probe_size == final_mtu) {
                        no_icmp_this_step = 0;
                        found_icmp = 1;
                        uint16_t nhmtu = icmp_info[k].next_hop_mtu;
                        if (nhmtu != final_mtu) {
                            // frag needed
                            fprintf(stderr,
                                    "[mtud_prober] Received ICMP Frag Needed => Next Hop MTU = %d\n",
                                    nhmtu);
                            final_mtu = nhmtu;
                        } else {
                            // time exceeded => final_mtu=현재 mtu
                            fprintf(stderr,
                                    "[mtud_prober] Received ICMP Time Exceeded => Use current test mtu = %d\n",
                                    final_mtu);
                        }
                        break;
                    }
                }
                pthread_mutex_unlock(&icmp_mutex);

                if (found_icmp) {
                    break; // step done
                }
            }
            free(send_buf);
        }
        if (!found_icmp && no_icmp_this_step) {
            fprintf(stderr,
                    "[mtud_prober] Step(A) no ICMP received with size=%d => degrade to next step\n",
                    final_mtu);
            continue;
        }
        // ICMP received => (A) done
        break;
    }
    if (!found_icmp && tries_idx >= 3) {
        // 1500 fail => 500
        final_mtu = 500;
        fprintf(stderr,
                "[mtud_prober] Step(A) => No ICMP even for 1500B. Fallback to 500.\n");
    }

    // stop icmp collector
    collecting = 0;
    if (icmp_sock >= 0) {
        pthread_join(icmp_thread, NULL);
        close(icmp_sock);
    }

    // ----------------------------------------
    // (B) 단계: DF=0, TTL=64
    // ----------------------------------------
    int val2 = IP_PMTUDISC_DONT;
    if (setsockopt(sock, IPPROTO_IP, IP_MTU_DISCOVER, &val2, sizeof(val2)) < 0) {
        perror("setsockopt(IP_MTU_DISCOVER, IP_PMTUDISC_DONT)");
    }
    int ttl2 = 64;
    if (setsockopt(sock, IPPROTO_IP, IP_TTL, &ttl2, sizeof(ttl2)) < 0) {
        perror("setsockopt(IP_TTL)");
    }

    fprintf(stderr,
            "\n[mtud_prober] Step(B): Sending final packet of size=%d to Destination\n",
            final_mtu);

    // Step(B) - 첫 번째 패킷: final_mtu
    send_and_record_test(sock, &dest_addr, final_mtu, test_count,
                         "Step(B) final_mtu", if_name);

    /*
    // ------------------------------
    // (추가) 여기에서 인터페이스 MTU를 9000으로 재설정 시도
    //       실패해도 종료 X, 계속 진행
    // ------------------------------
    {
        int ret_set9000 = try_set_mtu(if_name, 9000);
        if (ret_set9000 == 0) {
            fprintf(stderr,
                    "\n[mtud_prober] Step(B): Successfully set %s MTU to 9000 (for large packet tests)\n",
                    if_name);
        } else {
            fprintf(stderr,
                    "\n[mtud_prober] Step(B): Failed to set %s MTU to 9000, continuing anyway...\n",
                    if_name);
        }
    }
    */

    // ------------------------------
    // 이후 9000/8900/1500/1400/1000/500B 순서대로 전송
    // ------------------------------
    fprintf(stderr, "\n[mtud_prober] Step(B) Additional: Also sending 9000B packet\n");
    send_and_record_test(sock, &dest_addr, 9000, test_count,
                         "Step(B) Additional(9000B)", if_name);

    fprintf(stderr, "\n[mtud_prober] Step(B) Additional: Also sending 8900B packet\n");
    send_and_record_test(sock, &dest_addr, 8900, test_count,
                         "Step(B) Additional(8900B)", if_name);

    fprintf(stderr, "\n[mtud_prober] Step(B) Additional: Also sending 1500B packet\n");
    send_and_record_test(sock, &dest_addr, 1500, test_count,
                         "Step(B) Additional(1500B)", if_name);

    fprintf(stderr, "\n[mtud_prober] Step(B) Additional: Also sending 1400B packet\n");
    send_and_record_test(sock, &dest_addr, 1400, test_count,
                         "Step(B) Additional(1400B)", if_name);

    fprintf(stderr, "\n[mtud_prober] Step(B) Additional: Also sending 1000B packet\n");
    send_and_record_test(sock, &dest_addr, 1000, test_count,
                         "Step(B) Additional(1000B)", if_name);

    fprintf(stderr, "\n[mtud_prober] Step(B) Additional: Also sending 500B packet\n");
    send_and_record_test(sock, &dest_addr, 500, test_count,
                         "Step(B) Additional(500B)", if_name);

    /*
    // ------------------------------
    // (추가) 여기에서 인터페이스 MTU를 1500으로 재설정 시도
    //       실패해도 종료 X, 계속 진행
    // ------------------------------
    {
        int ret_set1500 = try_set_mtu(if_name, 1500);
        if (ret_set1500 == 0) {
            fprintf(stderr,
                    "\n[mtud_prober] Step(B): Successfully set %s MTU to 1500 (for large packet tests)\n",
                    if_name);
        } else {
            fprintf(stderr,
                    "\n[mtud_prober] Step(B): Failed to set %s MTU to 1500, continuing anyway...\n",
                    if_name);
        }
    }

    // ------------------------------
    // 이후 9000/8900/1500/1400/1000/500B 순서대로 전송
    // ------------------------------
    fprintf(stderr, "\n[mtud_prober] Step(B) Additional: Also sending 9000B packet with MTU = 1500\n");
    send_and_record_test(sock, &dest_addr, 9000, test_count,
                         "Step(B) Additional(9000B)", if_name);

    fprintf(stderr, "\n[mtud_prober] Step(B) Additional: Also sending 8900B packet with MTU = 1500\n");
    send_and_record_test(sock, &dest_addr, 8900, test_count,
                         "Step(B) Additional(8900B)", if_name);

    fprintf(stderr, "\n[mtud_prober] Step(B) Additional: Also sending 1500B packet with MTU = 1500\n");
    send_and_record_test(sock, &dest_addr, 1500, test_count,
                         "Step(B) Additional(1500B)", if_name);

    fprintf(stderr, "\n[mtud_prober] Step(B) Additional: Also sending 1400B packet with MTU = 1500\n");
    send_and_record_test(sock, &dest_addr, 1400, test_count,
                         "Step(B) Additional(1400B)", if_name);

    fprintf(stderr, "\n[mtud_prober] Step(B) Additional: Also sending 1000B packet with MTU = 1500\n");
    send_and_record_test(sock, &dest_addr, 1000, test_count,
                         "Step(B) Additional(1000B)", if_name);

    fprintf(stderr, "\n[mtud_prober] Step(B) Additional: Also sending 500B packet with MTU = 1500\n");
    send_and_record_test(sock, &dest_addr, 500, test_count,
                         "Step(B) Additional(500B)", if_name);
    */
    
    // 요약
    fprintf(stderr, "\n=== F-PMTUD Final Summary ===\n");
    fprintf(stderr, "Picked Interface: %s\n", if_name);
    fprintf(stderr, "Configured MTU: %d\n", configured_mtu_initial);
    fprintf(stderr, "Final Used MTU: %d\n", final_mtu);
    fprintf(stderr, "Prober IP: %s (Local MTU: %d)\n", local_ip, local_mtu);
    fprintf(stderr, "Destination IP: %s (Port: %d)\n", server_ip, server_port);

    for (int i = 0; i < test_count; i++) {
        if (test_success[i]) {
            fprintf(stderr,
                    "[Summary] Packet size=%d => success (max frag=%d)\n",
                    test_sizes[i], test_results[i]);
        } else {
            fprintf(stderr,
                    "[Summary] Packet size=%d => F-PMTUD failed\n",
                    test_sizes[i]);
        }
    }

    pthread_mutex_lock(&icmp_mutex);
    if (icmp_count == 0) {
        fprintf(stderr,
                "No ICMP packets (frag needed/time exceeded) received.\n");
    } else {
        for (int i = 0; i < icmp_count; i++) {
            fprintf(stderr,
                    "ICMP #%d => probe_size=%d, next_hop_mtu=%d\n",
                    i + 1,
                    icmp_info[i].probe_size,
                    icmp_info[i].next_hop_mtu);
        }
    }
    pthread_mutex_unlock(&icmp_mutex);

    // 종료 패킷
    ssize_t sent_exit = sendto(sock, EXIT_MARKER, strlen(EXIT_MARKER), 0,
                               (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    if (sent_exit < 0) {
        perror("[mtud_prober] Failed to send exit marker");
    } else {
        fprintf(stderr, "[mtud_prober] EXIT_MARKER sent to destination\n");
    }

    close(sock);
    free(server_ip);

    if (overall_success) {
        printf("F-PMTUD_prober SUCCESS\n");
    } else {
        printf("F-PMTUD_prober FAILED\n");
    }
    return 0;
}