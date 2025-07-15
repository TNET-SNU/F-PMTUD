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
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/ioctl.h>

#define BUFFER_SIZE     65536
#define MAX_TRACKED_IDS 100
#define MAGIC_MARKER    "FPMT"  // Identifier sent by client (4 bytes)
#define EXIT_MARKER     "FEXIT" // Shutdown request identifier (5 bytes)

// Fragment tracking structure
typedef struct {
    uint16_t ip_id;                // IP identification field
    int      received_payload_len; // Accumulated UDP data length
    int      expected_payload_len; // Total UDP data length (determined from first fragment)
    int      max_ip_len;           // Maximum IP packet length among fragments
    bool     complete;             // Flag indicating all fragments received
} PacketState;

// Global/static variables
static PacketState packet_states[MAX_TRACKED_IDS];
static size_t      num_tracked_ids  = 0;
static bool        exit_requested   = false;
static bool        port_bound       = false;

// Flag indicating overall success (set to 1 if any response is sent successfully)
static int overall_success = 0;

// -------------------------
// Functions for interface MTU configuration
// -------------------------

// Retrieve the first non-loopback IPv4 interface name
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

// Attempt to set MTU on given interface
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
        // Check for device MTU maximum error
        if (strstr(line, "Error: mtu greater than device maximum.")) {
            success = 0;
        }
    }
    pclose(fp);
    return success ? 0 : -1;
}

// -------------------------
// Remaining core functions
// -------------------------

/*
 * If socket isn't bound yet and a packet with fragments or the magic marker arrives,
 * attempt to bind the UDP socket to the destination port.
 * On failure, log error but continue processing.
 */
static void maybe_bind_udp_socket(int udp_sock, uint16_t dest_port)
{
    if (port_bound)
        return; // Already bound

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family      = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;  // Bind on all interfaces
    server_addr.sin_port        = dest_port;   // Network byte order

    if (bind(udp_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        if (errno == EADDRINUSE) {
            fprintf(stderr, "[mtud_destination] UDP bind failed: Address already in use on port %u. Ignoring and continuing.\n", ntohs(dest_port));
        } else {
            perror("[mtud_destination] UDP bind failed");
            fprintf(stderr, "[mtud_destination] Failed to bind port %u. Ignoring and continuing.\n", ntohs(dest_port));
        }
        return;  // Proceed even if bind failed
    }

    port_bound = true;
    fprintf(stderr, "[mtud_destination] Dynamically bound destination UDP socket to port %u\n", ntohs(dest_port));
}

// Find tracking index by IP ID
static int find_packet_state(uint16_t ip_id)
{
    for (size_t i = 0; i < num_tracked_ids; i++) {
        if (packet_states[i].ip_id == ip_id) {
            return i;
        }
    }
    return -1;
}

// Remove the oldest tracked state when exceeding limit
static void remove_oldest_packet_state()
{
    if (num_tracked_ids == 0)
        return;
    for (size_t i = 1; i < num_tracked_ids; i++) {
        packet_states[i - 1] = packet_states[i];
    }
    num_tracked_ids--;
}

// Add new tracked state for IP ID
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

// Check if packet is a PMTUD probe (non-fragmented)
static bool is_pmtud_packet(const char *payload, int payload_len)
{
    if (payload_len < 4)
        return false;
    return (memcmp(payload, MAGIC_MARKER, 4) == 0);
}

// Check if packet is an exit request
static bool is_exit_packet(const char *payload, int payload_len)
{
    if (payload_len < 5)
        return false;
    return (memcmp(payload, EXIT_MARKER, 5) == 0);
}

/*
 * Process each received raw packet, extract UDP fragments or probes,
 * track reassembly state, and send responses when complete.
 */
static void process_packet(char *buffer, ssize_t data_len, int udp_sock, struct sockaddr_in *client_addr)
{
    // Parse Ethernet header
    struct ethhdr *ethh = (struct ethhdr *)buffer;
    if (ntohs(ethh->h_proto) != ETH_P_IP)
        return; // Ignore non-IP packets

    // Parse IP header
    struct iphdr *iph = (struct iphdr *)(ethh + 1);
    if (iph->protocol != IPPROTO_UDP)
        return;  // Only handle UDP

    int ip_hdr_len = iph->ihl << 2;
    int ip_tot_len = ntohs(iph->tot_len);
    int ip_payload_len = ip_tot_len - ip_hdr_len;
    if (ip_payload_len < (int)sizeof(struct udphdr))
        return;

    // Parse UDP header
    struct udphdr *udph = (struct udphdr *)((char *)iph + ip_hdr_len);
    int udp_total_len = ntohs(udph->len);
    int udp_data_len  = udp_total_len - sizeof(struct udphdr);
    char *udp_payload = (char *)udph + sizeof(struct udphdr);

    uint16_t client_source_port = udph->source;  // Network order

    // Check for exit request
    if (is_exit_packet(udp_payload, udp_data_len)) {
        fprintf(stderr, "[mtud_destination] Exit packet received. Shutting down.\n");
        exit_requested = true;
        return;
    }

    // Determine if packet is fragmented
    uint16_t ip_frag = ntohs(iph->frag_off);
    bool is_fragmented = ((ip_frag & 0x1FFF) != 0) || (ip_frag & 0x2000);

    // For non-fragmented packets, require magic marker
    if (!is_fragmented) {
        if (udp_data_len < 4 || !is_pmtud_packet(udp_payload, udp_data_len))
            return;
    }

    // Bind UDP socket dynamically on first valid packet
    if (!port_bound)
        maybe_bind_udp_socket(udp_sock, udph->dest);

    if (!port_bound)
        return;

    uint16_t ip_id = ntohs(iph->id);

    // Non-fragmented case: respond immediately
    if (!is_fragmented) {
        fprintf(stderr, "[mtud_destination] Tracking new IP ID: %u (non-fragmented)\n", ip_id);
        client_addr->sin_family      = AF_INET;
        client_addr->sin_port        = client_source_port;
        client_addr->sin_addr.s_addr = iph->saddr;
        fprintf(stderr, "[mtud_destination] ID=%u, UDP length=%d\n", ip_id, udp_data_len + 8);
        fprintf(stderr, "[mtud_destination] Prober=%s:%d\n",
                inet_ntoa(client_addr->sin_addr), ntohs(client_addr->sin_port));

        int net_val = htonl(ip_tot_len);
        sendto(udp_sock, &net_val, sizeof(net_val), 0,
               (struct sockaddr *)client_addr, sizeof(*client_addr));
        overall_success = 1;
        return;
    }

    // Fragmented packet handling
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
        this_data = ip_payload_len - sizeof(struct udphdr); // First fragment includes UDP header
    else
        this_data = ip_payload_len; // Subsequent fragments carry only data
    st->received_payload_len += this_data;

    fprintf(stderr,
            "[mtud_destination] ID=%u, offset=%d, ip_tot_len=%d, cumul_udp_payload=%d\n",
            ip_id,
            8 * (ip_frag & 0x1FFF),
            ip_tot_len,
            st->received_payload_len);

    // On first fragment, record expected total UDP length and source info
    if (((ip_frag & 0x1FFF) == 0) && (st->expected_payload_len == 0)) {
        st->expected_payload_len = udp_data_len;
        client_addr->sin_family      = AF_INET;
        client_addr->sin_port        = client_source_port;
        client_addr->sin_addr.s_addr = iph->saddr;
        fprintf(stderr, "[mtud_destination] ID=%u, Prober=%s:%d\n",
                ip_id, inet_ntoa(client_addr->sin_addr), ntohs(client_addr->sin_port));
    }

    // When all fragments received, send response with largest packet size
    if (st->expected_payload_len > 0 &&
        st->received_payload_len >= st->expected_payload_len &&
        !st->complete) {
        st->complete = true;
        fprintf(stderr, "[mtud_destination] All fragments received! ID=%u\n", ip_id);
        fprintf(stderr, "[mtud_destination] Max IP packet size=%d\n", st->max_ip_len);
        int net_val = htonl(st->max_ip_len);
        sendto(udp_sock, &net_val, sizeof(net_val), 0,
               (struct sockaddr *)client_addr, sizeof(*client_addr));
        overall_success = 1;
    }
}

int main(void)
{
    // -------------------------------
    // Auto-detect interface and attempt MTU configuration
    // -------------------------------
    char if_name[IFNAMSIZ] = {0};
    if (get_first_nonlo_interface(if_name, sizeof(if_name)) < 0) {
        fprintf(stderr, "[mtud_destination] No suitable non-lo interface found. Proceeding without MTU config.\n");
    } else {
        // Try MTUs: 64000, 9000, 1500, fallback to 500
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

    // Create raw socket for packet inspection
    int raw_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if (raw_sock < 0) {
        perror("[mtud_destination] socket(AF_PACKET, SOCK_RAW, ETH_P_IP)");
        return 1;
    }

    // Create UDP socket for sending responses
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

    // Main loop: receive raw packets and process them
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

    // Final result to stdout
    if (overall_success) {
        printf("F-PMTUD_destination SUCCESS");
    } else {
        printf("F-PMTUD_destination FAILED");
    }
    return 0;
}