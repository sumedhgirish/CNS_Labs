from scapy.all import *
from scapy.layers.dns import DNS

ATTACKER_NS = "ns.attacker32.com"
ATTACKER_IFACE = "br-fa8ae839be42"


class Task:
    @staticmethod
    def _1():

        TARGET = "www.example.com"

        def spoof_dns(pkt):
            if DNS in pkt and TARGET in pkt[DNS].qd.qname.decode("utf-8"):
                print(pkt.summary())

        _ = sniff(iface=ATTACKER_IFACE, prn=spoof_dns, filter="port 53")


if __name__ == "__main__":
    Task()._1()
