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
#define MAGIC_MARKER "FPMT"    // 4-byte marker identifying probe packets
#define EXIT_MARKER  "FEXIT"   // 5-byte marker requesting shutdown
#define IP_HDR_SIZE  20        // Standard IPv4 header length without options
#define UDP_HDR_SIZE 8         // UDP header length

// ---------------------------------------------------
// ICMP-related globals
// ---------------------------------------------------
typedef struct {
    int probe_size;          // Size of packet sent when ICMP was received
    uint16_t next_hop_mtu;   // Next-hop MTU from ICMP "fragmentation needed"
} icmp_info_t;

#define MAX_ICMP_PACKETS 20
static icmp_info_t icmp_info[MAX_ICMP_PACKETS];
static int icmp_count = 0;

// Flag controlling whether the ICMP collector thread should keep running
static volatile int collecting = 1;

// Mutexes for thread-safe access to ICMP data and probe size
static pthread_mutex_t icmp_mutex  = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t probe_mutex = PTHREAD_MUTEX_INITIALIZER;

// Current probe packet size, read by ICMP thread
static volatile int current_probe_size = 0;

// Global success flag: set to 1 if any probe or fragment test succeeds
static int overall_success = 0;

// ---------------------------------------------------
// Arrays storing results of multiple packet tests
// ---------------------------------------------------
#define MAX_TESTS 20  // Total tests: initial + additional sizes
static int test_sizes[MAX_TESTS];      // Packet sizes tested
static int test_results[MAX_TESTS];    // Server-reported maximum fragment sizes
static int test_success[MAX_TESTS];    // 1 = success, 0 = failure
static int test_count = 0;             // Number of tests performed

// ---------------------------------------------------
// Print usage instructions
// ---------------------------------------------------
static void print_usage(const char *prog_name) {
    fprintf(stderr, "Usage: %s -i <Destination IP> [-p <Destination Port>] [-P <Prober Port>]\n",
            prog_name);
}

// ---------------------------------------------------
// Determine local IP address by connecting UDP socket and using getsockname
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
// Retrieve MTU of the interface assigned to local_ip via ioctl(SIOCGIFMTU)
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
// Get first non-loopback IPv4 interface name
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
    return found ? 0 : -1;
}

// ---------------------------------------------------
// Set interface MTU via system
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
            (strstr(line, "Error") && !strstr(line, "mtu"))) {
            success = 0;
        }
    }
    pclose(fp);
    return success ? 0 : -1;
}

// ---------------------------------------------------
// ICMP collector thread: listens for "frag needed" or "time exceeded"
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

        int probe_size_snapshot;
        pthread_mutex_lock(&probe_mutex);
        probe_size_snapshot = current_probe_size;
        pthread_mutex_unlock(&probe_mutex);

        // "Fragmentation needed" messages
        if (icmp_hdr->type == ICMP_DEST_UNREACH && icmp_hdr->code == 4) {
            if (len < ip_header_len + sizeof(struct icmphdr) + sizeof(uint16_t))
                continue; // not enough data for next-hop MTU
            uint16_t next_hop_mtu = ntohs(*(uint16_t *)((unsigned char *)icmp_hdr + 6));
            pthread_mutex_lock(&icmp_mutex);
            if (icmp_count < MAX_ICMP_PACKETS) {
                icmp_info[icmp_count].probe_size   = probe_size_snapshot;
                icmp_info[icmp_count].next_hop_mtu = next_hop_mtu;
                icmp_count++;
            }
            pthread_mutex_unlock(&icmp_mutex);
        }
        // "Time exceeded" messages
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
// Send probe and record results for step (B)
// ---------------------------------------------------
static void send_and_record_test(int sock,
                                 const struct sockaddr_in *dest_addr,
                                 int test_size,
                                 int idx,
                                 const char *info_label,
                                 const char *if_name)
{
    if (test_count >= MAX_TESTS) {
        fprintf(stderr, "[mtud_prober] Maximum number of tests reached. Skipping %d.\n", test_size);
        return;
    }

    test_sizes[test_count]   = test_size;
    test_results[test_count] = -1;
    test_success[test_count] = 0;

    int payload_len = test_size - IP_HDR_SIZE - UDP_HDR_SIZE;
    if (payload_len < 4) {
        fprintf(stderr,
                "[mtud_prober] %s: packet size %d too small for header+marker.\n",
                info_label, test_size);
        test_count++;
        return;
    }
    char *buf = calloc(1, payload_len);
    if (!buf) {
        perror("[mtud_prober] calloc in send_and_record_test");
        test_count++;
        return;
    }
    memcpy(buf, MAGIC_MARKER, 4);

    int attempts = 0;
    int got_response = 0;
    while (attempts < 3 && !got_response) {
        attempts++;
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
                "[mtud_prober] %s: sent UDP %zd bytes -> total %d (attempt %d)\n",
                info_label, sent + UDP_HDR_SIZE, test_size, attempts);

        char response[sizeof(int)];
        ssize_t ret_recv = recv(sock, response, sizeof(response), 0);
        if (ret_recv == (ssize_t)sizeof(response)) {
            int server_result = ntohl(*(int *)response);
            got_response      = 1;
            overall_success   = 1;
            test_success[test_count] = 1;
            test_results[test_count] = server_result;

            fprintf(stderr,
                    "Probe size: %d, server max frag: %d\n",
                    test_size, server_result);
        } else if (ret_recv < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            fprintf(stderr,
                    "[mtud_prober] %s: no response (attempt %d)\n",
                    info_label, attempts);
        } else if (ret_recv < 0) {
            perror("[mtud_prober] recv error in send_and_record_test");
        }
    }
    if (!got_response) {
        fprintf(stderr,
                "Probe size: %d, F-PMTUD failed\n",
                test_size);
    }
    free(buf);
    test_count++;
}

// ---------------------------------------------------
// Main function
// ---------------------------------------------------
int main(int argc, char *argv[]) {
    char *server_ip  = NULL;
    int server_port  = 9999;
    int client_port  = 0;
    int opt;

    // Parse command-line options
    while ((opt = getopt(argc, argv, "i:p:P:")) != -1) {
        switch (opt) {
            case 'i': server_ip  = strdup(optarg); break;
            case 'p': server_port = atoi(optarg);    break;
            case 'P': client_port = atoi(optarg);    break;
            default:
                print_usage(argv[0]);
                exit(EXIT_FAILURE);
        }
    }
    if (!server_ip) {
        print_usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    // Set up destination address
    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, server_ip, &dest_addr.sin_addr) <= 0) {
        fprintf(stderr, "Invalid destination IP: %s\n", server_ip);
        exit(EXIT_FAILURE);
    }
    dest_addr.sin_port = htons(server_port);

    // Select interface and attempt MTU configuration
    char if_name[IFNAMSIZ] = {0};
    if (get_first_nonlo_interface(if_name, sizeof(if_name)) < 0) {
        fprintf(stderr, "[mtud_prober] No non-loopback interface found. Exiting.\n");
        exit(EXIT_FAILURE);
    }
    fprintf(stderr, "[mtud_prober] Using interface: %s\n", if_name);

    int initial_tries[3] = {64000, 9000, 1500};
    int configured_mtu_initial = 500;
    int set_ok_initial = 0;
    for (int i = 0; i < 3; i++) {
        if (try_set_mtu(if_name, initial_tries[i]) == 0) {
            configured_mtu_initial = initial_tries[i];
            set_ok_initial = 1;
            fprintf(stderr, "[mtud_prober] Set %s MTU to %d\n",
                    if_name, configured_mtu_initial);
            break;
        } else {
            fprintf(stderr, "[mtud_prober] Failed to set %s MTU to %d\n",
                    if_name, initial_tries[i]);
        }
    }
    if (!set_ok_initial) {
        fprintf(stderr, "[mtud_prober] Fallback %s MTU = 500\n", if_name);
    }

    // Create UDP socket for sending probes
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket(AF_INET, SOCK_DGRAM)");
        exit(EXIT_FAILURE);
    }

    // Bind to client port if provided
    if (client_port > 0) {
        struct sockaddr_in client_addr;
        memset(&client_addr, 0, sizeof(client_addr));
        client_addr.sin_family      = AF_INET;
        client_addr.sin_addr.s_addr = INADDR_ANY;
        client_addr.sin_port        = htons(client_port);

        if (bind(sock, (struct sockaddr *)&client_addr, sizeof(client_addr)) < 0) {
            perror("bind() for prober port");
            close(sock);
            exit(EXIT_FAILURE);
        }
        fprintf(stderr, "[mtud_prober] Bound to port %d\n", client_port);
    }

    // Set up ICMP raw socket for error messages
    int icmp_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (icmp_sock < 0) {
        perror("[mtud_prober] ICMP raw socket failed");
    } else {
        int flags = fcntl(icmp_sock, F_GETFL, 0);
        fcntl(icmp_sock, F_SETFL, flags | O_NONBLOCK);
    }
    pthread_t icmp_thread;
    if (icmp_sock >= 0) {
        pthread_create(&icmp_thread, NULL, icmp_collector, &icmp_sock);
    }

    // Enable Path MTU Discovery (DF=1) and set low TTL for step (A)
    int val = IP_PMTUDISC_DO;
    setsockopt(sock, IPPROTO_IP, IP_MTU_DISCOVER, &val, sizeof(val));
    int ttl = 2;
    setsockopt(sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));

    // Set receive timeout to 1 second
    struct timeval timeout = {1, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    // Determine local IP and MTU for summary
    char local_ip[INET_ADDRSTRLEN] = {0};
    if (get_local_ip(local_ip, sizeof(local_ip), server_ip, server_port) != 0) {
        strncpy(local_ip, "Unknown", sizeof(local_ip));
    }
    int local_mtu = get_interface_mtu(local_ip);
    if (local_mtu <= 0) local_mtu = 1500;
    fprintf(stderr, "[mtud_prober] Local IP: %s, MTU: %d\n",
            local_ip, local_mtu);

    // ------------------------------------------------
    // Step (A): DF=1, TTL=2: send decreasing packet sizes until ICMP
    // ------------------------------------------------
    int final_mtu = configured_mtu_initial;
    int found_icmp = 0;
    int idx = (configured_mtu_initial == 64000)?0:
              (configured_mtu_initial == 9000)?1:
              (configured_mtu_initial == 1500)?2:3;

    for (; idx < 3; idx++) {
        final_mtu = initial_tries[idx];
        fprintf(stderr, "[mtud_prober] Step(A): trying size=%d\n", final_mtu);

        int no_icmp = 1;
        int udp_plen = final_mtu - IP_HDR_SIZE - UDP_HDR_SIZE;
        if (udp_plen >= 4) {
            char *send_buf = calloc(1, udp_plen);
            memcpy(send_buf, MAGIC_MARKER, 4);
            for (int attempt = 1; attempt <= 3; attempt++) {
                pthread_mutex_lock(&probe_mutex);
                current_probe_size = final_mtu;
                pthread_mutex_unlock(&probe_mutex);

                sendto(sock, send_buf, udp_plen, 0,
                       (struct sockaddr *)&dest_addr, sizeof(dest_addr));
                sleep(1);
                pthread_mutex_lock(&icmp_mutex);
                for (int k = 0; k < icmp_count; k++) {
                    if (icmp_info[k].probe_size == final_mtu) {
                        no_icmp = 0;
                        found_icmp = 1;
                        uint16_t nhmtu = icmp_info[k].next_hop_mtu;
                        if (nhmtu != final_mtu) {
                            fprintf(stderr,
                                    "[mtud_prober] ICMP frag needed: NH-MTU=%d\n", nhmtu);
                            final_mtu = nhmtu;
                        } else {
                            fprintf(stderr,
                                    "[mtud_prober] ICMP time exceeded: keep=%d\n", final_mtu);
                        }
                        break;
                    }
                }
                pthread_mutex_unlock(&icmp_mutex);
                if (found_icmp) break;
            }
            free(send_buf);
        }
        if (found_icmp || !no_icmp) break;
        fprintf(stderr, "[mtud_prober] no ICMP for %d -> next\n", final_mtu);
    }
    if (!found_icmp && idx >= 3) {
        final_mtu = 500;
        fprintf(stderr, "[mtud_prober] Step(A) fallback to 500\n");
    }

    // Stop ICMP collectors
    collecting = 0;
    if (icmp_sock >= 0) {
        pthread_join(icmp_thread, NULL);
        close(icmp_sock);
    }

    // ------------------------------------------------
    // Step (B): DF=0, TTL=64, send final and additional sizes
    // ------------------------------------------------
    int val2 = IP_PMTUDISC_DONT;
    setsockopt(sock, IPPROTO_IP, IP_MTU_DISCOVER, &val2, sizeof(val2));
    int ttl2 = 64;
    setsockopt(sock, IPPROTO_IP, IP_TTL, &ttl2, sizeof(ttl2));

    fprintf(stderr,
            "\n[mtud_prober] Step(B): final size=%d\n", final_mtu);
    send_and_record_test(sock, &dest_addr, final_mtu, test_count,
                         "Step(B) final", if_name);

    // Additional test sizes
    int extras[] = {9000, 8900, 1500, 1400, 1000, 500};
    for (int j=0; j<6; j++) {
        fprintf(stderr, "\n[mtud_prober] Step(B) Additional: size=%d\n", extras[j]);
        send_and_record_test(sock, &dest_addr, extras[j], test_count,
                             "Step(B) additional", if_name);
    }

    // Print summary
    fprintf(stderr, "\n=== F-PMTUD Final Summary ===\n");
    fprintf(stderr, "Interface: %s, Initial MTU: %d, Final MTU: %d\n",
            if_name, configured_mtu_initial, final_mtu);
    fprintf(stderr, "Local IP: %s (MTU: %d), Dest: %s:%d\n",
            local_ip, local_mtu, server_ip, server_port);
    for (int i=0; i<test_count; i++) {
        if (test_success[i]) {
            fprintf(stderr, "[Summary] size=%d -> success (max frag=%d)\n",
                    test_sizes[i], test_results[i]);
        } else {
            fprintf(stderr, "[Summary] size=%d -> failure\n", test_sizes[i]);
        }
    }
    pthread_mutex_lock(&icmp_mutex);
    if (icmp_count == 0) {
        fprintf(stderr, "No ICMP errors received.\n");
    } else {
        for (int i=0; i<icmp_count; i++) {
            fprintf(stderr, "ICMP #%d: probe=%d, next-hop MTU=%d\n",
                    i+1, icmp_info[i].probe_size, icmp_info[i].next_hop_mtu);
        }
    }
    pthread_mutex_unlock(&icmp_mutex);

    // Send exit marker to destination
    sendto(sock, EXIT_MARKER, strlen(EXIT_MARKER), 0,
           (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    fprintf(stderr, "[mtud_prober] EXIT_MARKER sent\n");

    close(sock);
    free(server_ip);

    if (overall_success) {
        printf("F-PMTUD_prober SUCCESS\n");
    } else {
        printf("F-PMTUD_prober FAILED\n");
    }
    return 0;
}
