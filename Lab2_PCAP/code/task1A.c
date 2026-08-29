#include <assert.h>
#include <ctype.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netdb.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define PACKET(Name, HeaderT)                                                                      \
    typedef struct {                                                                               \
        HeaderT header;                                                                            \
        u_char data[];                                                                             \
    } Name

PACKET(eth_t, struct ether_header);
PACKET(ip_t, struct iphdr);
PACKET(tcp_t, struct tcphdr);

void make_safe(u_char* payload, int payload_len) {
    for (int idx = 0; idx < payload_len; ++idx) {
        if (!isprint(payload[idx])) {
            payload[idx] = '.';
        }
    }
}

void print_packet(u_char* user, const struct pcap_pkthdr* header, const u_char* packet) {
    eth_t* link_pkt = (eth_t*)packet;

    if (ntohs(link_pkt->header.ether_type) == ETHERTYPE_IP) {
        ip_t* ip_pkt = (ip_t*)link_pkt->data;

        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];

        inet_ntop(AF_INET, &ip_pkt->header.saddr, src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &ip_pkt->header.daddr, dst_ip, INET_ADDRSTRLEN);
        struct protoent* proto = getprotobynumber(ip_pkt->header.protocol);

        printf("IP(");
        printf("src_ip: %s, ", src_ip);
        printf("dst_ip: %s, ", dst_ip);
        printf("proto: %s", proto->p_name);
        printf(")");

        if (ip_pkt->header.protocol == IPPROTO_TCP) {
            tcp_t* tcp_pkt = (tcp_t*)ip_pkt->data;

            make_safe(tcp_pkt->data, ntohs(ip_pkt->header.tot_len - sizeof(ip_t) - sizeof(tcp_t)));

            printf(" / TCP(");
            printf("src_port: %d, ", tcp_pkt->header.th_sport);
            printf("dst_port: %d", tcp_pkt->header.th_dport);
            printf(")");
            printf(" / Data(%s)", tcp_pkt->data);
        }

        printf("\n");
    }
}

#define LOG_ON_ERROR(exp, handle)                                                                  \
    if (exp != 0) {                                                                                \
        pcap_perror(handle, "Error: ");                                                            \
        exit(EXIT_FAILURE);                                                                        \
    }

void apply_filter(pcap_t* handle, char* filter_exp) {
    struct bpf_program fp;
    bpf_u_int32 net;

    pcap_compile(handle, &fp, filter_exp, 1, net);
    LOG_ON_ERROR(pcap_setfilter(handle, &fp), handle);
}

char* find_bridge_interface(pcap_if_t* alldevsp) {
    pcap_if_t* current = alldevsp;

    while (current != NULL) {
        if (current->name != NULL) {
            if (strncmp(current->name, "br-", 3) == 0) {
                return current->name;
            }
        }
        current = current->next;
    }

    return NULL;
}

int main(int argc, const char* argv[]) {
    pcap_if_t* alldevsp = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_findalldevs(&alldevsp, errbuf);

    char* default_dev = find_bridge_interface(alldevsp);
    printf("Using device %s.\n", default_dev);

    pcap_t* handle = pcap_open_live("eth0", 262144, 1, 1000, errbuf);

    // apply_filter(handle, "icmp");
    // apply_filter(handle, "icmp and (host 10.9.0.5 and 10.9.0.6)");
    apply_filter(handle, "tcp src port 23");

    pcap_loop(handle, -1, print_packet, NULL);

    pcap_close(handle);
}
