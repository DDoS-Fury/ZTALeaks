"""
Test offline per snort-mid (SQLi e XSS, sid 3000001-3000014).
Mandiamo un flusso TCP completo verso porta 8081 (ext_authz path) con
payload HTTP che contiene il pattern target.
"""

import pytest

from helpers import tcp_flow


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
