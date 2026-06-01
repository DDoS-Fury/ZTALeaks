"""
Test offline per la rule del snort base (sid 1000001 - TCP port scanning).
detection_filter: track by_src, count 5, seconds 5.
Generiamo 6 SYN da stesso src verso porte diverse in 1 secondo.
"""

from scapy.all import IP, TCP

from helpers import CLIENT_IP, SERVER_IP


def test_port_scan(snort_offline):
    pkts = []
    t0 = 1700000000.0
    for i, port in enumerate([22, 80, 443, 3306, 5432, 8443]):
        p = IP(src=CLIENT_IP, dst=SERVER_IP) / TCP(sport=40000 + i, dport=port, flags="S", seq=1000 + i)
        p.time = t0 + i * 0.1
        pkts.append(p)

    alerts = snort_offline("snort", pkts)
    sids = {a.sid for a in alerts}
    assert "1000001" in sids, f"sid:1000001 (port scan) non triggerato; alerts={sids}"
