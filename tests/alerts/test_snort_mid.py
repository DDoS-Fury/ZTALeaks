"""
Test offline per snort-mid (SQLi e XSS, sid 3000001-3000014).
Mandiamo un flusso TCP completo verso porta 8081 (ext_authz path) con
payload HTTP che contiene il pattern target.
"""

import pytest

from helpers import tcp_flow, tcp_flow_split


def _http_get(path: str) -> bytes:
    return f"GET {path} HTTP/1.1\r\nHost: x\r\n\r\n".encode()


@pytest.mark.parametrize("sid,payload", [
    ("3000001", _http_get("/api?q=UNION+SELECT+*+FROM+users")),
    ("3000002", _http_get("/api?u=admin'+OR+1=1--")),
    ("3000003", _http_get("/api?x=DROP+TABLE+users")),
    ("3000004", _http_get("/api?q=%27+OR+%271%27%3D%271")),
    ("3000010", _http_get("/api?x=<script>alert(1)</script>")),
    ("3000011", _http_get("/api?x=%3Cscript%3Ealert(1)")),
    ("3000012", _http_get("/api?x=javascript:alert(1)")),
    ("3000013", _http_get("/api?x=<img+src=x+onerror=alert(1)>")),
    ("3000014", _http_get("/api?x=<body+onload=alert(1)>")),
])
def test_snort_mid_alert(snort_offline, sid, payload):
    pkts = tcp_flow(payload, dport=8081)
    alerts = snort_offline("snort-mid", pkts)
    sids = {a.sid for a in alerts}
    assert sid in sids, f"sid:{sid} non triggerato; alerts={sids}"


def _realistic_extauthz_request_with_sqli() -> bytes:
    """
    Riproduce il payload reale generato da Envoy verso :8081 quando
    `forward_client_cert_details: SANITIZE_SET` e `cert: true` sono attivi:
    l'header `X-Forwarded-Client-Cert` contiene il certificato client PEM
    URL-encoded (~2 KB), che porta la richiesta sopra il singolo MSS.
    Il SQLi UNION SELECT e' inserito nello `X-Original-Uri`.
    """
    # Cert PEM URL-encoded preso dai certs di test del repo (operator1.crt).
    # Lo simuliamo con un blob della stessa forma e dimensione realistica.
    pem_body = b"MIIEejCCAmKgAwIBAgIUbB2GK717jX5ch7WNFuR3lhIazBQwDQYJKoZIhvcNAQEL" * 24  # ~1.5 KB
    xfcc = (
        b"Hash=6c381a1811b5a97138d435158062bc460be1a268f5e348055013b427490682fa;"
        b"Cert=\"-----BEGIN%20CERTIFICATE-----%0A" + pem_body + b"%0A-----END%20CERTIFICATE-----%0A\";"
        b"Subject=\"OU=operator,CN=operator1,O=ZTA-Leaks,C=IT\";URI="
    )
    body = (
        b"POST /api/v1/evaluate HTTP/1.1\r\n"
        b"Host: security-orchestrator:8081\r\n"
        b"X-Forwarded-Client-Cert: " + xfcc + b"\r\n"
        b"X-Original-Uri: /api/v1/personnel?q=UNION+SELECT+*+FROM+users\r\n"
        b"X-Authz-Request-Path: /api/v1/personnel\r\n"
        b"X-Authz-Request-Method: GET\r\n"
        b"X-Request-Id: 00000000-0000-0000-0000-000000000001\r\n"
        b"Content-Length: 0\r\n\r\n"
    )
    return body


def test_sqli_payload_split_across_tcp_segments(snort_offline):
    """
    Regressione del KNOWN ISSUE del commit 2df7d06: con un payload
    ext_authz realistico (~2 KB, dominato da `x-forwarded-client-cert`),
    la richiesta viene spezzata su piu' segmenti TCP. Il SQLi finisce
    in un segmento separato dal resto e le rule raw-TCP-content non
    matchano oltre i confini di pacchetto.
    """
    payload = _realistic_extauthz_request_with_sqli()
    # Forza lo split in mezzo a "UNION" cosi' nessun singolo segmento
    # contiene la stringa intera.
    split_at = payload.index(b"UNION") + 2
    pkts = tcp_flow_split(payload, split_at=split_at, dport=8081)
    alerts = snort_offline("snort-mid", pkts)
    sids = {a.sid for a in alerts}
    assert "3000001" in sids, f"sid:3000001 non triggerato su payload split (~{len(payload)}B); alerts={sids}"
