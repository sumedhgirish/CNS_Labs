from scapy.all import *
from scapy.layers.inet import ICMP, IP

BRIDGE_INTERFACE = "br-8a478ee85e99"


## ============================================================================
# Task 1.1
#
# Part A:
#   TODO: Demonstrate that you can capture the packets
#
# Part B:
#   TODO: Learn to filter the captured packets
#           (a) Filter only ICMP packets
#           (b) Filter TCP packets on port 23 from a given IP
#           (c) Filter packets under a given subnet
#
# =============================================================================


class Task1:
    @staticmethod
    def _1A():
        def capture(pkt):
            print(pkt.summary(), flush=True)

        _ = sniff(iface=BRIDGE_INTERFACE, prn=capture)

    @staticmethod
    def _1B():
        def capture(pkt):
            print(pkt.summary(), flush=True)

        filterA = "icmp"
        filterB = "tcp and src host 10.9.0.5 and dst port 23"
        filterC = "net 10.9.0.0/16"

        _ = sniff(iface=BRIDGE_INTERFACE, filter=filterB, prn=capture)

    @staticmethod
    def _2A():
        pkt = IP(src="10.9.0.1", dst="10.9.0.5") / ICMP()
        send(pkt, verbose=False)

    @staticmethod
    def _2B():
        pkt = IP(src="10.9.0.6", dst="10.9.0.5") / ICMP()
        send(pkt, verbose=False)

    @staticmethod
    def _3(target):
        ttl = 1
        while True:
            pkt = IP(dst=target, ttl=ttl) / ICMP()
            reply = sr1(pkt, verbose=False, timeout=2)

            if not reply:
                print(f"{ttl:3} hops: * * *", flush=True)
                ttl += 1
                continue

            print(f"{ttl:3} hops: {reply[IP].src}", flush=True)
            if reply[ICMP].type == 0:
                print(f"Done. Terminated at {reply[IP].src}.", flush=True)
                break
            elif reply[ICMP].type == 11:
                ttl += 1
            else:
                print(
                    f"Stopped by ICMP Type {reply[ICMP].type} at {reply[IP].src}.",
                    flush=True,
                )
                break

    @staticmethod
    def _4():
        def spoof_ICMP(pkt):
            if IP in pkt and ICMP in pkt and pkt[ICMP].type == 8:
                print(f"Spoofed packet from {pkt[IP].src}", end=" | ")

                pkt = (
                    IP(src=pkt[IP].dst, dst=pkt[IP].src, ihl=pkt[IP].ihl)
                    / ICMP(type=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq)
                    / pkt[ICMP].load
                )

                print(f"Sending {pkt.summary()}", flush=True)
                send(pkt, verbose=False)

        _ = sniff(iface=BRIDGE_INTERFACE, prn=spoof_ICMP)


if __name__ == "__main__":
    print("\nTraceroute: Google")
    Task1._3("8.8.8.8")
    print("\nTraceroute: HostA")
    Task1._3("10.9.0.5")
    print("\nTraceroute: Cloudflare")
    Task1._3("1.1.1.1")
