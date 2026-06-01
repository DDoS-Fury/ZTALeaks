"""
Test offline per snort-internal (12 alert):
- 1000004 ICMP echo (canary)
- 2000002 mTLS Violation (empty Certificate handshake)
- 2000006 SYN flood verso porta 8443
- 2000010-12 ClientHello con legacy_version vulnerabile
- 2000020-22 ServerHello negoziato con legacy version (downgrade)
- 2000030-32 ClientHello che offre cipher suite deboli
"""

import pytest
from scapy.all import IP, TCP, ICMP, Raw

from helpers import (
    CLIENT_IP, SERVER_IP,
    tcp_flow, client_hello, server_hello,
)


# ---------- 1000004 ICMP echo ----------

def test_icmp_echo(snort_offline):
    pkt = IP(src=CLIENT_IP, dst=SERVER_IP) / ICMP(type=8)
    alerts = snort_offline("snort-internal", [pkt])
    sids = {a.sid for a in alerts}
    assert "1000004" in sids, f"sid:1000004 (ICMP) non triggerato; alerts={sids}"


# ---------- 2000002 mTLS Violation: empty Certificate handshake ----------

def test_mtls_empty_certificate(snort_offline):
    # Handshake type 0x0B (Certificate) con length 3 e certificate_list_length 0:
    #   0B 00 00 03 00 00 00
    pkts = tcp_flow(b"\x0B\x00\x00\x03\x00\x00\x00", dport=8443)
    alerts = snort_offline("snort-internal", pkts)
    sids = {a.sid for a in alerts}
    assert "2000002" in sids, f"sid:2000002 (mTLS violation) non triggerato; alerts={sids}"


# ---------- 2000006 SYN flood ----------

def test_syn_flood(snort_offline):
    """detection_filter: track by_dst, count 30, seconds 2 (rule punta a porta 8443)."""
    pkts = []
    t0 = 1700000000.0
    for i in range(35):
        p = IP(src=CLIENT_IP, dst=SERVER_IP) / TCP(sport=40000 + i, dport=8443, flags="S", seq=2000 + i)
        p.time = t0 + i * 0.05  # 35 pacchetti in ~1.75s
        pkts.append(p)
    alerts = snort_offline("snort-internal", pkts)
    sids = {a.sid for a in alerts}
    assert "2000006" in sids, f"sid:2000006 (SYN flood) non triggerato; alerts={sids}"


# ---------- 2000010-12 ClientHello con legacy_version ----------

@pytest.mark.parametrize("sid,legacy_version", [
    ("2000010", b"\x03\x00"),  # SSLv3
    ("2000011", b"\x03\x01"),  # TLS 1.0
    ("2000012", b"\x03\x02"),  # TLS 1.1
])
def test_clienthello_legacy_version(snort_offline, sid, legacy_version):
    payload = client_hello(legacy_version=legacy_version)
    pkts = tcp_flow(payload, dport=8443)
    alerts = snort_offline("snort-internal", pkts)
    sids = {a.sid for a in alerts}
    assert sid in sids, f"sid:{sid} non triggerato; alerts={sids}"


# ---------- 2000020-22 ServerHello downgrade ----------

@pytest.mark.parametrize("sid,server_version", [
    ("2000020", b"\x03\x00"),  # SSLv3
    ("2000021", b"\x03\x01"),  # TLS 1.0
    ("2000022", b"\x03\x02"),  # TLS 1.1
])
def test_serverhello_downgrade(snort_offline, sid, server_version):
    payload = server_hello(version=server_version)
    # Per matchare flow:from_server, il payload deve viaggiare dal server (sport=8443)
    pkts = tcp_flow(payload, dport=8443, from_server=True)
    alerts = snort_offline("snort-internal", pkts)
    sids = {a.sid for a in alerts}
    assert sid in sids, f"sid:{sid} non triggerato; alerts={sids}"


# ---------- 2000030-32 Weak cipher offered ----------

@pytest.mark.parametrize("sid,cipher_suites", [
    ("2000030", b"\x00\x05"),          # RC4 (TLS_RSA_WITH_RC4_128_SHA)
    ("2000031", b"\x00\x0A"),          # 3DES (TLS_RSA_WITH_3DES_EDE_CBC_SHA)
    ("2000032", b"\x00\x03"),          # EXPORT (TLS_RSA_EXPORT_WITH_RC4_40_MD5)
])
def test_clienthello_weak_cipher(snort_offline, sid, cipher_suites):
    payload = client_hello(cipher_suites=cipher_suites)
    pkts = tcp_flow(payload, dport=8443)
    alerts = snort_offline("snort-internal", pkts)
    sids = {a.sid for a in alerts}
    assert sid in sids, f"sid:{sid} non triggerato; alerts={sids}"
