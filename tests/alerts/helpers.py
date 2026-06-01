"""
Primitive scapy condivise dai test alert (offline-pcap).
"""

from scapy.all import IP, TCP, ICMP, Raw

CLIENT_IP = "10.0.0.10"
SERVER_IP = "10.0.0.20"


def tcp_flow(payload: bytes, dport: int = 8081, sport: int = 54321,
             src: str = CLIENT_IP, dst: str = SERVER_IP,
             from_server: bool = False):
    """
    Flusso TCP completo (3WH + data + teardown).
    Se `from_server=True`, il payload viaggia da `dst` (sport=dport del 3WH)
    verso `src`, utile per testare rule con flow:from_server.
    """
    cli, srv = src, dst
    seq_c, seq_s = 1000, 5000

    syn      = IP(src=cli, dst=srv)/TCP(sport=sport, dport=dport, flags="S",  seq=seq_c)
    syn_ack  = IP(src=srv, dst=cli)/TCP(sport=dport, dport=sport, flags="SA", seq=seq_s, ack=seq_c+1)
    ack      = IP(src=cli, dst=srv)/TCP(sport=sport, dport=dport, flags="A",  seq=seq_c+1, ack=seq_s+1)

    if from_server:
        data     = IP(src=srv, dst=cli)/TCP(sport=dport, dport=sport, flags="PA", seq=seq_s+1, ack=seq_c+1)/Raw(load=payload)
        data_ack = IP(src=cli, dst=srv)/TCP(sport=sport, dport=dport, flags="A",  seq=seq_c+1, ack=seq_s+1+len(payload))
        fin_a    = IP(src=srv, dst=cli)/TCP(sport=dport, dport=sport, flags="FA", seq=seq_s+1+len(payload), ack=seq_c+1)
        fin_b    = IP(src=cli, dst=srv)/TCP(sport=sport, dport=dport, flags="FA", seq=seq_c+1, ack=seq_s+2+len(payload))
        last     = IP(src=srv, dst=cli)/TCP(sport=dport, dport=sport, flags="A",  seq=seq_s+2+len(payload), ack=seq_c+2)
    else:
        data     = IP(src=cli, dst=srv)/TCP(sport=sport, dport=dport, flags="PA", seq=seq_c+1, ack=seq_s+1)/Raw(load=payload)
        data_ack = IP(src=srv, dst=cli)/TCP(sport=dport, dport=sport, flags="A",  seq=seq_s+1, ack=seq_c+1+len(payload))
        fin_a    = IP(src=cli, dst=srv)/TCP(sport=sport, dport=dport, flags="FA", seq=seq_c+1+len(payload), ack=seq_s+1)
        fin_b    = IP(src=srv, dst=cli)/TCP(sport=dport, dport=sport, flags="FA", seq=seq_s+1, ack=seq_c+2+len(payload))
        last     = IP(src=cli, dst=srv)/TCP(sport=sport, dport=dport, flags="A",  seq=seq_c+2+len(payload), ack=seq_s+2)

    return [syn, syn_ack, ack, data, data_ack, fin_a, fin_b, last]


def tcp_flow_split(payload: bytes, split_at: int,
                   dport: int = 8081, sport: int = 54321,
                   src: str = CLIENT_IP, dst: str = SERVER_IP):
    """
    Come tcp_flow ma il payload client->server è spezzato in due
    PSH-ACK segmenti consecutivi, simulando frammentazione TCP.
    Riproduce lo scenario del KNOWN ISSUE del commit 2df7d06
    (x-forwarded-client-cert che fa fragmentare la ext_authz request).
    """
    cli, srv = src, dst
    seq_c, seq_s = 1000, 5000
    p1, p2 = payload[:split_at], payload[split_at:]

    syn      = IP(src=cli, dst=srv)/TCP(sport=sport, dport=dport, flags="S",  seq=seq_c)
    syn_ack  = IP(src=srv, dst=cli)/TCP(sport=dport, dport=sport, flags="SA", seq=seq_s, ack=seq_c+1)
    ack      = IP(src=cli, dst=srv)/TCP(sport=sport, dport=dport, flags="A",  seq=seq_c+1, ack=seq_s+1)

    data1    = IP(src=cli, dst=srv)/TCP(sport=sport, dport=dport, flags="PA", seq=seq_c+1,           ack=seq_s+1)/Raw(load=p1)
    ack1     = IP(src=srv, dst=cli)/TCP(sport=dport, dport=sport, flags="A",  seq=seq_s+1,           ack=seq_c+1+len(p1))
    data2    = IP(src=cli, dst=srv)/TCP(sport=sport, dport=dport, flags="PA", seq=seq_c+1+len(p1),   ack=seq_s+1)/Raw(load=p2)
    ack2     = IP(src=srv, dst=cli)/TCP(sport=dport, dport=sport, flags="A",  seq=seq_s+1,           ack=seq_c+1+len(payload))

    fin_a    = IP(src=cli, dst=srv)/TCP(sport=sport, dport=dport, flags="FA", seq=seq_c+1+len(payload), ack=seq_s+1)
    fin_b    = IP(src=srv, dst=cli)/TCP(sport=dport, dport=sport, flags="FA", seq=seq_s+1,           ack=seq_c+2+len(payload))
    last     = IP(src=cli, dst=srv)/TCP(sport=sport, dport=dport, flags="A",  seq=seq_c+2+len(payload), ack=seq_s+2)

    return [syn, syn_ack, ack, data1, ack1, data2, ack2, fin_a, fin_b, last]


# --- TLS handshake primitives ---

def tls_record(content_type: int, version: bytes, body: bytes) -> bytes:
    """TLS record: type(1) + version(2) + length(2) + payload."""
    return bytes([content_type]) + version + len(body).to_bytes(2, "big") + body


def client_hello(legacy_version: bytes = b"\x03\x03", cipher_suites: bytes = b"\x00\x2F") -> bytes:
    """
    ClientHello minimale. `cipher_suites` è concatenazione raw di codici 2B.
    `legacy_version` è il field a offset 9-10 del payload TCP (quello che le
    rule sid:2000010-12 controllano).
    """
    body = (
        legacy_version
        + b"\x00" * 32                          # random
        + b"\x00"                               # session_id length
        + len(cipher_suites).to_bytes(2, "big") # cipher_suites length
        + cipher_suites
        + b"\x01\x00"                           # compression methods: 1 byte, null
    )
    # Wrap nel record TLS + handshake header (type 0x01 = ClientHello)
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return tls_record(0x16, b"\x03\x01", hs)


def server_hello(version: bytes, cipher: bytes = b"\x00\x2F") -> bytes:
    """
    ServerHello con `version` come legacy_version a offset 9-10
    (campo testato dalle rule sid:2000020-22).
    """
    body = (
        version
        + b"\x00" * 32
        + b"\x00"      # session_id length
        + cipher       # selected cipher (2B)
        + b"\x00"      # compression method
    )
    hs = b"\x02" + len(body).to_bytes(3, "big") + body
    return tls_record(0x16, b"\x03\x01", hs)
