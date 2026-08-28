#include <assert.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netdb.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>

#define PACKET(Name, HeaderT)                                                                      \
    typedef struct {                                                                               \
        HeaderT header;                                                                            \
        u_char data[];                                                                             \
    } Name

PACKET(eth_t, struct ether_header);
PACKET(ip_t, struct iphdr);
PACKET(icmp_t, struct icmphdr);

void swap(unsigned int* a, unsigned int* b) {
    unsigned int tmp = *b;
    *b = *a;
    *a = tmp;
}

unsigned short in_checksum(unsigned short* data, int length) {
    unsigned short* curr = data;
    unsigned int sum = 0;

    while (length > 1) {
        sum += *curr++;
        length -= 2;
    }

    if (length == 1) {
        unsigned short temp = 0;
        *(u_char*)&temp = *(u_char*)curr;
        sum += temp;
    }

    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    return (unsigned short)(~sum);
}

void send_icmp_packet(ip_t* pkt, int total_len) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        perror("socket error");
        return;
    }

    int header_incl = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &header_incl, sizeof(header_incl)) < 0) {
        perror("setsockopt error");
        close(sock);
        return;
    }

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    memcpy(&dest.sin_addr, &pkt->header.daddr, sizeof(pkt->header.daddr));

    if (sendto(sock, pkt, total_len, 0, (struct sockaddr*)&dest, sizeof(dest)) < 0) {
        perror("sendto error");
    }

    close(sock);
}

void spoofer(u_char* user, const struct pcap_pkthdr* header, const u_char* packet) {
    int ip_hdr_len = sizeof(struct iphdr);
    int min_len = sizeof(eth_t) + ip_hdr_len + sizeof(struct icmphdr);

    if ((int)header->caplen < min_len)
        return;

    eth_t* eth_pkt = (eth_t*)packet;

    if (ntohs(eth_pkt->header.ether_type) == ETHERTYPE_IP) {
        ip_t* ip_pkt = (ip_t*)eth_pkt->data;

        if (ip_pkt->header.protocol == IPPROTO_ICMP) {
            icmp_t* icmp_pkt = (icmp_t*)ip_pkt->data;

            // Handle ICMP Echo Requests (Type 8)
            if (icmp_pkt->header.type == ICMP_ECHO) {
                int total_ip_len = ntohs(ip_pkt->header.tot_len);
                int icmp_len = total_ip_len - (ip_pkt->header.ihl * 4);

                // Create a mutable copy of the IP frame
                u_char* reply_buf = malloc(total_ip_len);
                if (!reply_buf)
                    return;

                memcpy(reply_buf, ip_pkt, total_ip_len);
                ip_t* reply_ip = (ip_t*)reply_buf;
                icmp_t* reply_icmp = (icmp_t*)reply_ip->data;

                // 1. Convert Echo Request to Echo Reply
                reply_icmp->header.type = ICMP_ECHOREPLY;
                reply_icmp->header.checksum = 0;
                reply_icmp->header.checksum = in_checksum((unsigned short*)reply_icmp, icmp_len);

                // 2. Swap Source and Destination IP Addresses
                swap(&reply_ip->header.saddr, &reply_ip->header.daddr);

                // 3. Recalculate IP Header Checksum
                reply_ip->header.check = 0;
                reply_ip->header.check =
                    in_checksum((unsigned short*)reply_ip, reply_ip->header.ihl * 4);

                // 4. Send the spoofed reply
                send_icmp_packet(reply_ip, total_ip_len);

                free(reply_buf);
            }
        }
    }
}

#define LOG_ON_ERROR(exp, handle)                                                                  \
    if (exp != 0) {                                                                                \
        pcap_perror(handle, "Error: ");                                                            \
        exit(EXIT_FAILURE);                                                                        \
    }

void apply_filter(pcap_t* handle, const char* filter_exp) {
    struct bpf_program fp;
    bpf_u_int32 net = PCAP_NETMASK_UNKNOWN;

    if (pcap_compile(handle, &fp, filter_exp, 1, net) < 0) {
        pcap_perror(handle, "pcap_compile error");
        exit(EXIT_FAILURE);
    }
    LOG_ON_ERROR(pcap_setfilter(handle, &fp), handle);
    pcap_freecode(&fp);
}

int main(int argc, const char* argv[]) {
    pcap_if_t* alldevsp = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevsp, errbuf) < 0 || alldevsp == NULL) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return EXIT_FAILURE;
    }

    char* default_dev = alldevsp->name;
    printf("Using device %s.\n", default_dev);

    pcap_t* handle = pcap_open_live(default_dev, 262144, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        pcap_freealldevs(alldevsp);
        return EXIT_FAILURE;
    }

    apply_filter(handle, "icmp and icmp[icmptype] == icmp-echo");

    printf("Sniffing for ICMP Echo Requests...\n");
    pcap_loop(handle, -1, spoofer, NULL);

    pcap_close(handle);
    pcap_freealldevs(alldevsp);
    return EXIT_SUCCESS;
}
