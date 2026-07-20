#!/usr/bin/env python3
"""
generate_test_traffic.py
=========================
CodeAlpha Cyber Security Internship — Task 4 (Network IDS)

Builds a synthetic .pcap file containing a mix of:
  - benign traffic (normal HTTP GET, a single ping, a short DNS query)
  - traffic patterns that SHOULD trigger custom.rules:
      * a TCP port scan (many SYNs to different ports)
      * an ICMP ping sweep
      * one oversized ICMP packet
      * a plaintext HTTP POST containing "password="
      * an HTTP request with a scanner User-Agent (sqlmap)
      * an FTP anonymous login attempt
      * an unusually long DNS query
      * plaintext Telnet traffic

This is for TESTING OUR OWN DETECTION RULES OFFLINE. No packets are sent on
any real network or interface — everything is written to a local .pcap file
that Suricata later reads in --pcap replay mode. This does not attack, scan,
or contact any real host.
"""

from scapy.all import Ether, IP, TCP, UDP, ICMP, DNS, DNSQR, Raw, wrpcap

ATTACKER = "203.0.113.50"     # TEST-NET-3 documentation address (RFC 5737)
VICTIM = "192.168.1.100"      # Falls inside Suricata's default HOME_NET
DNS_SERVER = "8.8.8.8"
CLIENT = "192.168.1.50"       # A normal internal client, for benign traffic

MAC_A = "aa:aa:aa:aa:aa:aa"
MAC_B = "bb:bb:bb:bb:bb:bb"

packets = []


def tcp_session(src, dst, sport, dport, payload=None, mac_src=MAC_A, mac_dst=MAC_B):
    """Build a minimal, well-formed TCP handshake (+ optional payload + close)
    so Suricata's stream engine and app-layer parsers can follow it."""
    seq_c, seq_s = 1000, 5000
    pkts = []
    eth_cs = Ether(src=mac_src, dst=mac_dst)
    eth_sc = Ether(src=mac_dst, dst=mac_src)

    # 3-way handshake
    pkts.append(eth_cs / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="S", seq=seq_c))
    seq_c += 1
    pkts.append(eth_sc / IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="SA", seq=seq_s, ack=seq_c))
    seq_s += 1
    pkts.append(eth_cs / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="A", seq=seq_c, ack=seq_s))

    if payload:
        pkts.append(eth_cs / IP(src=src, dst=dst) /
                     TCP(sport=sport, dport=dport, flags="PA", seq=seq_c, ack=seq_s) /
                     Raw(load=payload))
        seq_c += len(payload)
        pkts.append(eth_sc / IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="A", seq=seq_s, ack=seq_c))

    # graceful close
    pkts.append(eth_cs / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="FA", seq=seq_c, ack=seq_s))
    seq_c += 1
    pkts.append(eth_sc / IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="FA", seq=seq_s, ack=seq_c))
    seq_s += 1
    pkts.append(eth_cs / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="A", seq=seq_c, ack=seq_s))
    return pkts


# ---------------------------------------------------------------------------
# 1) Benign traffic — should NOT trigger any alert
# ---------------------------------------------------------------------------
normal_http = (b"GET / HTTP/1.1\r\nHost: example.com\r\n"
               b"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
               b"Accept: text/html\r\n\r\n")
packets += tcp_session(CLIENT, "93.184.216.34", 45111, 80, payload=normal_http)

packets.append(Ether(src=MAC_A, dst=MAC_B) / IP(src=CLIENT, dst=DNS_SERVER) /
                UDP(sport=51000, dport=53) / DNS(rd=1, qd=DNSQR(qname="example.com")))

packets.append(Ether(src=MAC_A, dst=MAC_B) / IP(src=CLIENT, dst="192.168.1.1") / ICMP(type=8, id=1, seq=1))
packets.append(Ether(src=MAC_B, dst=MAC_A) / IP(src="192.168.1.1", dst=CLIENT) / ICMP(type=0, id=1, seq=1))

# ---------------------------------------------------------------------------
# 2) Port scan — 25 SYNs from the attacker to different ports on the victim
# ---------------------------------------------------------------------------
for port in range(20, 45):
    packets.append(Ether(src=MAC_A, dst=MAC_B) / IP(src=ATTACKER, dst=VICTIM) /
                    TCP(sport=40000 + port, dport=port, flags="S", seq=port * 10))

# ---------------------------------------------------------------------------
# 3) ICMP ping sweep — 25 rapid echo requests from the attacker
# ---------------------------------------------------------------------------
for i in range(25):
    packets.append(Ether(src=MAC_A, dst=MAC_B) / IP(src=ATTACKER, dst=VICTIM) /
                    ICMP(type=8, id=999, seq=i))

# ---------------------------------------------------------------------------
# 4) Oversized ICMP packet (>1024 byte payload)
# ---------------------------------------------------------------------------
packets.append(Ether(src=MAC_A, dst=MAC_B) / IP(src=ATTACKER, dst=VICTIM) /
                ICMP(type=8, id=1000, seq=1) / Raw(load=b"A" * 1200))

# ---------------------------------------------------------------------------
# 5) Cleartext HTTP POST with password= in the body
# ---------------------------------------------------------------------------
login_body = b"username=admin&password=SuperSecret123"
http_post = (b"POST /login HTTP/1.1\r\nHost: intranet.local\r\n"
             b"Content-Type: application/x-www-form-urlencoded\r\n"
             b"Content-Length: " + str(len(login_body)).encode() + b"\r\n\r\n" + login_body)
packets += tcp_session(CLIENT, VICTIM, 46000, 80, payload=http_post)

# ---------------------------------------------------------------------------
# 6) HTTP request with a scanner User-Agent (sqlmap)
# ---------------------------------------------------------------------------
sqlmap_req = (b"GET /product?id=1' HTTP/1.1\r\nHost: shop.local\r\n"
              b"User-Agent: sqlmap/1.6.12#stable (http://sqlmap.org)\r\n\r\n")
packets += tcp_session(ATTACKER, VICTIM, 46100, 80, payload=sqlmap_req)

nikto_req = (b"GET /admin/ HTTP/1.1\r\nHost: shop.local\r\n"
             b"User-Agent: Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:map_codes)\r\n\r\n")
packets += tcp_session(ATTACKER, VICTIM, 46110, 80, payload=nikto_req)

nmap_req = (b"GET / HTTP/1.1\r\nHost: shop.local\r\n"
            b"User-Agent: Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)\r\n\r\n")
packets += tcp_session(ATTACKER, VICTIM, 46120, 80, payload=nmap_req)

# ---------------------------------------------------------------------------
# 7) FTP anonymous login attempt
# ---------------------------------------------------------------------------
ftp_cmds = b"USER anonymous\r\n"
packets += tcp_session(ATTACKER, VICTIM, 46200, 21, payload=ftp_cmds)

# ---------------------------------------------------------------------------
# 8) Unusually long DNS query (possible tunneling)
# ---------------------------------------------------------------------------
long_label = "aGVsbG93b3JsZHRoaXNpc2FzdXNwaWNpb3VzbHlsb25nZW5jb2RlZHN1YmRvbWFpbg"
packets.append(Ether(src=MAC_A, dst=MAC_B) / IP(src=ATTACKER, dst=DNS_SERVER) /
                UDP(sport=52000, dport=53) /
                DNS(rd=1, qd=DNSQR(qname=f"{long_label}.example.com")))

# ---------------------------------------------------------------------------
# 9) Plaintext Telnet traffic
# ---------------------------------------------------------------------------
packets += tcp_session(CLIENT, VICTIM, 46300, 23, payload=b"login: admin\r\n")

wrpcap("test_traffic.pcap", packets)
print(f"Wrote {len(packets)} packets to test_traffic.pcap")
