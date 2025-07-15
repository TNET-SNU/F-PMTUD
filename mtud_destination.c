#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <linux/if_packet.h>

// 추가된 헤더들
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/ioctl.h>

#define BUFFER_SIZE     65536
#define MAX_TRACKED_IDS 100
#define MAGIC_MARKER    "FPMT"  // 클라이언트에서 보낸 식별자 (4바이트)
#define EXIT_MARKER     "FEXIT" // 종료 요청 식별자 (5바이트)

// 단편 추적 구조체
typedef struct {
    uint16_t ip_id;                // IP 식별자
    int      received_payload_len; // 누적 UDP 데이터 길이
    int      expected_payload_len; // 전체 UDP 데이터 길이(첫 단편에서 파악)
    int      max_ip_len;           // 단편들 중 최대 IP 패킷 길이
    bool     complete;             // 모든 단편 수신 완료 여부
} PacketState;

// 전역/정적 변수
static PacketState packet_states[MAX_TRACKED_IDS];
static size_t      num_tracked_ids  = 0;
static bool        exit_requested   = false;
static bool        port_bound       = false;

// 최종 성공 여부 플래그 (하나라도 정상 응답 전송에 성공하면 1)
static int overall_success = 0;

// -------------------------
// 추가: 인터페이스 MTU 설정에 필요한 함수들
// -------------------------

// "lo" 제외, 첫 번째 IPv4 인터페이스 이름 얻기
static int get_first_nonlo_interface(char *if_name_out, size_t size) {
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) != 0) {
        perror("[mtud_destination] getifaddrs");
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

// 인터페이스 MTU 설정 시도
static int try_set_mtu(const char *ifname, int mtu_val) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "sudo ip link set dev %s mtu %d 2>&1", ifname, mtu_val);

    FILE *fp = popen(cmd, "r");
    if (!fp) {
        fprintf(stderr, "[mtud_destination] Failed to run command: %s\n", cmd);
        return -1;
    }
    int success = 1;
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "Error: mtu greater than device maximum.")) {
            success = 0;
        }
    }
    pclose(fp);
    return success ? 0 : -1;
}

// -------------------------
// 나머지 기존 함수들
// -------------------------

/*
 * 만약 아직 bind가 되지 않은 상태에서, 분할된 패킷이나 FPMT 마커가 포함된 패킷을 수신하면,
 * 해당 UDP 목적지 포트로 bind를 시도함.
 * 만약 bind()가 실패하면 에러 메시지만 출력하고 계속 진행.
 */
static void maybe_bind_udp_socket(int udp_sock, uint16_t dest_port)
{
    if (port_bound)
        return; // 이미 bind됨

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family      = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;  // 모든 인터페이스
    server_addr.sin_port        = dest_port;   // network byte order 그대로

    if (bind(udp_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        if (errno == EADDRINUSE) {
            fprintf(stderr, "[mtud_destination] UDP bind failed: Address already in use on port %u. Ignoring and continuing.\n", ntohs(dest_port));
        } else {
            perror("[mtud_destination] UDP bind failed");
            fprintf(stderr, "[mtud_destination] Failed to bind port %u. Ignoring and continuing.\n", ntohs(dest_port));
        }
        return;  // bind되지 않았더라도 종료시키지 않고 계속 진행
    }

    port_bound = true;
    fprintf(stderr, "[mtud_destination] Dynamically bound destination UDP socket to port %u\n", ntohs(dest_port));
}

static int find_packet_state(uint16_t ip_id)
{
    for (size_t i = 0; i < num_tracked_ids; i++) {
        if (packet_states[i].ip_id == ip_id) {
            return i;
        }
    }
    return -1;
}

static void remove_oldest_packet_state()
{
    if (num_tracked_ids == 0)
        return;
    for (size_t i = 1; i < num_tracked_ids; i++) {
        packet_states[i - 1] = packet_states[i];
    }
    num_tracked_ids--;
}

static int add_packet_state(uint16_t ip_id)
{
    if (num_tracked_ids >= MAX_TRACKED_IDS) {
        fprintf(stderr, "[mtud_destination] Too many tracked IDs. Removing oldest.\n");
        remove_oldest_packet_state();
    }
    packet_states[num_tracked_ids] = (PacketState){
        .ip_id = ip_id,
        .received_payload_len = 0,
        .expected_payload_len = 0,
        .max_ip_len = 0,
        .complete = false
    };
    return num_tracked_ids++;
}

// PMTUD 패킷 여부
static bool is_pmtud_packet(const char *payload, int payload_len)
{
    if (payload_len < 4)
        return false;
    return (memcmp(payload, MAGIC_MARKER, 4) == 0);
}

// 종료 요청 패킷 여부
static bool is_exit_packet(const char *payload, int payload_len)
{
    if (payload_len < 5)
        return false;
    return (memcmp(payload, EXIT_MARKER, 5) == 0);
}

/*
 * 수신한 RAW 패킷 처리 함수
 */
static void process_packet(char *buffer, ssize_t data_len, int udp_sock, struct sockaddr_in *client_addr)
{
    // 이더넷 헤더
    struct ethhdr *ethh = (struct ethhdr *)buffer;
    if (ntohs(ethh->h_proto) != ETH_P_IP)
        return; // IP 패킷이 아니면 무시

    // IP 헤더
    struct iphdr *iph = (struct iphdr *)(ethh + 1);
    if (iph->protocol != IPPROTO_UDP)
        return;  // UDP 패킷만 처리

    int ip_hdr_len = iph->ihl << 2;
    int ip_tot_len = ntohs(iph->tot_len);
    int ip_payload_len = ip_tot_len - ip_hdr_len;
    if (ip_payload_len < (int)sizeof(struct udphdr))
        return;

    // UDP 헤더
    struct udphdr *udph = (struct udphdr *)((char *)iph + ip_hdr_len);
    int udp_total_len = ntohs(udph->len);
    int udp_data_len  = udp_total_len - sizeof(struct udphdr);
    char *udp_payload = (char *)udph + sizeof(struct udphdr);

    uint16_t client_source_port = udph->source;  // network order 그대로

    // 종료 요청 패킷 체크
    if (is_exit_packet(udp_payload, udp_data_len)) {
        fprintf(stderr, "[mtud_destination] Exit packet received. Shutting down.\n");
        exit_requested = true;
        return;
    }

    // 패킷의 분할 여부 확인
    uint16_t ip_frag = ntohs(iph->frag_off);
    bool is_fragmented = ((ip_frag & 0x1FFF) != 0) || (ip_frag & 0x2000);

    // 비분할인 경우: UDP payload의 처음 4바이트에 MAGIC_MARKER가 있어야 함
    if (!is_fragmented) {
        if (udp_data_len < 4 || !is_pmtud_packet(udp_payload, udp_data_len))
            return; // 마커 없으면 무시
    }
    // 분할된 패킷은 마커 유무와 관계없이 처리

    if (!port_bound)
        maybe_bind_udp_socket(udp_sock, udph->dest);

    if (!port_bound)
        return;

    uint16_t ip_id = ntohs(iph->id);

    // 비분할 패킷
    if (!is_fragmented) {
        fprintf(stderr, "[mtud_destination] Tracking new IP ID: %u (non-fragmented)\n", ip_id);
        client_addr->sin_family      = AF_INET;
        client_addr->sin_port        = client_source_port;
        client_addr->sin_addr.s_addr = iph->saddr;
        fprintf(stderr, "[mtud_destination] ID=%u, UDP length=%d\n", ip_id, udp_data_len + 8);
        fprintf(stderr, "[mtud_destination] Prober=%s:%d\n",
                inet_ntoa(client_addr->sin_addr),
                ntohs(client_addr->sin_port));
        int net_val = htonl(ip_tot_len);
        sendto(udp_sock, &net_val, sizeof(net_val), 0,
               (struct sockaddr *)client_addr, sizeof(*client_addr));
        overall_success = 1;  // 성공적인 응답 전송
        return;
    }

    // 분할된 패킷
    int idx = find_packet_state(ip_id);
    if (idx == -1) {
        idx = add_packet_state(ip_id);
        fprintf(stderr, "[mtud_destination] Tracking new IP ID: %u (fragmented)\n", ip_id);
    }
    PacketState *st = &packet_states[idx];

    if (ip_tot_len > st->max_ip_len)
        st->max_ip_len = ip_tot_len;

    int this_data = 0;
    if ((ip_frag & 0x1FFF) == 0)
        this_data = ip_payload_len - sizeof(struct udphdr); // 첫 단편: UDP 헤더 포함
    else
        this_data = ip_payload_len; // 나머지 단편: 순수 payload
    st->received_payload_len += this_data;

    fprintf(stderr,
            "[mtud_destination] ID=%u, offset=%d, ip_tot_len=%d, cumul_udp_payload=%d\n",
            ip_id,
            8 * (ip_frag & 0x1FFF),
            ip_tot_len,
            st->received_payload_len);

    if (((ip_frag & 0x1FFF) == 0) && (st->expected_payload_len == 0)) {
        // 첫 단편에서 전체 UDP 길이
        st->expected_payload_len = udp_data_len;
        client_addr->sin_family      = AF_INET;
        client_addr->sin_port        = client_source_port;
        client_addr->sin_addr.s_addr = iph->saddr;
        fprintf(stderr, "[mtud_destination] ID=%u, Prober=%s:%d\n",
                ip_id, inet_ntoa(client_addr->sin_addr), ntohs(client_addr->sin_port));
    }

    if (st->expected_payload_len > 0 &&
        st->received_payload_len >= st->expected_payload_len &&
        !st->complete) {
        st->complete = true;
        fprintf(stderr, "[mtud_destination] All fragments received! ID=%u\n", ip_id);
        fprintf(stderr, "[mtud_destination] Max IP packet size=%d\n", st->max_ip_len);
        int net_val = htonl(st->max_ip_len);
        sendto(udp_sock, &net_val, sizeof(net_val), 0,
               (struct sockaddr *)client_addr, sizeof(*client_addr));
        overall_success = 1;  // 성공적인 응답 전송
    }
}

int main(void)
{
    // -------------------------------
    // (추가) 인터페이스 자동 탐색 + MTU 설정
    // -------------------------------
    char if_name[IFNAMSIZ] = {0};
    if (get_first_nonlo_interface(if_name, sizeof(if_name)) < 0) {
        fprintf(stderr, "[mtud_destination] No suitable non-lo interface found. Proceeding without MTU config.\n");
    } else {
        // 64000->9000->1500->fallback=500
        int tries[3] = {64000, 9000, 1500};
        int configured_mtu = 500;
        int set_ok = 0;

        for (int i = 0; i < 3; i++) {
            if (try_set_mtu(if_name, tries[i]) == 0) {
                configured_mtu = tries[i];
                set_ok = 1;
                fprintf(stderr,
                        "[mtud_destination] Successfully set %s MTU to %d\n",
                        if_name, configured_mtu);
                break;
            } else {
                fprintf(stderr,
                        "[mtud_destination] Failed to set %s MTU to %d\n",
                        if_name, tries[i]);
            }
        }
        if (!set_ok) {
            configured_mtu = 500;
            fprintf(stderr,
                    "[mtud_destination] Could not set %s MTU to 1500 either. Fallback to 500.\n",
                    if_name);
        }
    }

    // RAW 소켓 생성 (패킷 분석용)
    int raw_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if (raw_sock < 0) {
        perror("[mtud_destination] socket(AF_PACKET, SOCK_RAW, ETH_P_IP)");
        return 1;
    }

    // UDP 소켓 생성 (응답 전송용)
    int udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_sock < 0) {
        perror("[mtud_destination] UDP socket creation failed");
        close(raw_sock);
        return 1;
    }

    fprintf(stderr, "[mtud_destination] Waiting for the first PMTUD/EXIT packet to determine destination port...\n");

    char *buffer = calloc(1, BUFFER_SIZE);
    if (!buffer) {
        perror("[mtud_destination] calloc failed");
        close(raw_sock);
        close(udp_sock);
        return 1;
    }

    struct sockaddr_in client_addr;
    memset(&client_addr, 0, sizeof(client_addr));

    // 메인 루프: RAW 소켓으로 IP 패킷 수신 → process_packet
    while (1) {
        ssize_t data_len = recv(raw_sock, buffer, BUFFER_SIZE, 0);
        if (data_len < 0) {
            if (errno == EINTR)
                continue;
            perror("[mtud_destination] recv failed");
            break;
        }
        process_packet(buffer, data_len, udp_sock, &client_addr);
        if (exit_requested)
            break;
    }

    fprintf(stderr, "[mtud_destination] Destination is shutting down normally.\n");

    free(buffer);
    close(raw_sock);
    close(udp_sock);

    // 최종 결과 stdout
    if (overall_success) {
        printf("F-PMTUD_destination SUCCESS");
    } else {
        printf("F-PMTUD_destination FAILED");
    }
    return 0;
}
