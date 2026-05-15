"""
tests/snort/test_snort_internal.py

Test suite per gli alert di snort-internal (traffico Firewall -> Envoy).

Questi test inviano traffico reale verso il sistema live (localhost:8443)
e verificano che gli alert compaiano nel volume di log snort-internal.

Prerequisiti:
  - Stack ZTALeaks avviato: docker compose -f deployments/docker/docker-compose.yaml up -d
  - Certificati presenti in ./certs/ (ca.crt, client.crt, client.key)
  - pip install requests

Esecuzione:
  python -m pytest tests/snort/test_snort_internal.py -v
  oppure
  python tests/snort/test_snort_internal.py
"""

import socket
import ssl
import struct
import time
import subprocess
import sys
import os
import unittest

# ---------------------------------------------------------------------------
# Configurazione
# ---------------------------------------------------------------------------
TARGET_HOST = "localhost"
TARGET_PORT = int(os.environ.get("ENVOY_PORT", 8443))
LOG_POLL_TIMEOUT = 15       # secondi massimi di attesa per un alert nel log
LOG_POLL_INTERVAL = 0.5     # intervallo di polling del log

CERTS_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "certs")
CA_CERT    = os.path.join(CERTS_DIR, "ca.crt")
CLIENT_CERT = os.path.join(CERTS_DIR, "client.crt")
CLIENT_KEY  = os.path.join(CERTS_DIR, "client.key")

# Nome del container Snort internal per leggere il volume di log
SNORT_INTERNAL_CONTAINER = "ztaleaks_snort_internal"
LOG_PATH_IN_CONTAINER    = "/var/log/ztaleaks/snort-internal/alert_json.txt"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_log_tail(n_lines: int = 50) -> str:
    """Legge le ultime n_lines dal file di log snort-internal dentro Docker."""
    result = subprocess.run(
        ["docker", "exec", SNORT_INTERNAL_CONTAINER,
         "tail", f"-n{n_lines}", LOG_PATH_IN_CONTAINER],
        capture_output=True, text=True
    )
    return result.stdout


def _wait_for_alert(keyword: str, timeout: float = LOG_POLL_TIMEOUT) -> bool:
    """
    Polling del log fino a trovare keyword o scadere il timeout.
    Ritorna True se l'alert è stato trovato, False altrimenti.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        if keyword in _get_log_tail():
            return True
        time.sleep(LOG_POLL_INTERVAL)
    return False


def _send_raw_tcp(payload: bytes, host: str = TARGET_HOST, port: int = TARGET_PORT) -> None:
    """Apre una connessione TCP raw e invia il payload (senza TLS handshake)."""
    with socket.create_connection((host, port), timeout=3) as s:
        s.sendall(payload)
        # Legge un po' di risposta per non causare RST immediato
        try:
            s.recv(256)
        except Exception:
            pass


def _make_tls_client_hello(record_version: bytes, hello_version: bytes,
                            cipher_suites: bytes) -> bytes:
    """
    Costruisce un ClientHello TLS minimo.

    record_version: 2 byte (es. b'\\x03\\x01' per TLS 1.0)
    hello_version:  2 byte (versione nel ClientHello body)
    cipher_suites:  sequenza di cipher suite (es. b'\\x00\\x05' per RC4-SHA)

    Struttura TLS record:
      Content-Type (1B) | Version (2B) | Length (2B) | Handshake data
    Struttura Handshake:
      HandshakeType (1B) | Length (3B) | ClientHello body
    ClientHello body:
      Version (2B) | Random (32B) | SessionID len (1B) | CipherSuites len (2B) | CipherSuites | ...
    """
    random_bytes = os.urandom(32)
    # Numero di cipher suite (2 byte per suite)
    cs_len = struct.pack("!H", len(cipher_suites))

    client_hello_body = (
        hello_version +          # client_version
        random_bytes +           # random
        b"\x00" +                # session_id length = 0
        cs_len +                 # cipher_suites length
        cipher_suites +          # cipher_suites
        b"\x01\x00"              # compression_methods: 1 method, null
    )

    handshake = (
        b"\x01" +                         # HandshakeType: ClientHello
        struct.pack("!I", len(client_hello_body))[1:] +  # 3-byte length
        client_hello_body
    )

    record = (
        b"\x16" +                         # Content-Type: Handshake
        record_version +                  # Record version
        struct.pack("!H", len(handshake)) +  # Length
        handshake
    )
    return record


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

class TestSnortInternalAlerts(unittest.TestCase):

    # -----------------------------------------------------------------------
    # TLS Downgrade
    # -----------------------------------------------------------------------

    def test_sslv3_downgrade(self):
        """Invia un ClientHello con version record SSLv3 (0x03 0x00)."""
        payload = _make_tls_client_hello(
            record_version=b"\x03\x00",   # SSLv3 record
            hello_version=b"\x03\x00",    # SSLv3 hello
            cipher_suites=b"\x00\x35",    # AES-256-CBC-SHA (qualsiasi suite valida)
        )
        _send_raw_tcp(payload)
        found = _wait_for_alert("TLS Downgrade Detected (SSLv3)")
        self.assertTrue(found,
            "Alert 'SSLv3 Downgrade' non trovato nel log snort-internal entro il timeout.")

    def test_tls10_downgrade(self):
        """Invia un ClientHello con version record TLS 1.0 (0x03 0x01)."""
        payload = _make_tls_client_hello(
            record_version=b"\x03\x01",
            hello_version=b"\x03\x01",
            cipher_suites=b"\x00\x35",
        )
        _send_raw_tcp(payload)
        found = _wait_for_alert("TLS Downgrade Detected (TLS 1.0)")
        self.assertTrue(found,
            "Alert 'TLS 1.0 Downgrade' non trovato nel log snort-internal entro il timeout.")

    def test_tls11_downgrade(self):
        """Invia un ClientHello con version record TLS 1.1 (0x03 0x02)."""
        payload = _make_tls_client_hello(
            record_version=b"\x03\x02",
            hello_version=b"\x03\x02",
            cipher_suites=b"\x00\x35",
        )
        _send_raw_tcp(payload)
        found = _wait_for_alert("TLS Downgrade Detected (TLS 1.1)")
        self.assertTrue(found,
            "Alert 'TLS 1.1 Downgrade' non trovato nel log snort-internal entro il timeout.")

    # -----------------------------------------------------------------------
    # Weak Cipher Suites
    # -----------------------------------------------------------------------

    def test_weak_cipher_rc4_sha(self):
        """
        Invia un ClientHello TLS 1.2 che propone RC4-SHA (0x00 0x05).
        RC4 è crittograficamente rotto (RFC 7465).
        """
        payload = _make_tls_client_hello(
            record_version=b"\x03\x03",   # TLS 1.2 record (legale)
            hello_version=b"\x03\x03",
            cipher_suites=b"\x00\x05",    # TLS_RSA_WITH_RC4_128_SHA
        )
        _send_raw_tcp(payload)
        found = _wait_for_alert("Weak Cipher Suite Detected (RC4-SHA)")
        self.assertTrue(found,
            "Alert 'RC4-SHA' non trovato nel log snort-internal entro il timeout.")

    def test_weak_cipher_rc4_md5(self):
        """
        Invia un ClientHello TLS 1.2 che propone RC4-MD5 (0x00 0x04).
        """
        payload = _make_tls_client_hello(
            record_version=b"\x03\x03",
            hello_version=b"\x03\x03",
            cipher_suites=b"\x00\x04",    # TLS_RSA_WITH_RC4_128_MD5
        )
        _send_raw_tcp(payload)
        found = _wait_for_alert("Weak Cipher Suite Detected (RC4-MD5)")
        self.assertTrue(found,
            "Alert 'RC4-MD5' non trovato nel log snort-internal entro il timeout.")

    def test_weak_cipher_3des(self):
        """
        Invia un ClientHello TLS 1.2 che propone 3DES-EDE-CBC-SHA (0x00 0x0A).
        Vulnerabile a SWEET32 (CVE-2016-2183).
        """
        payload = _make_tls_client_hello(
            record_version=b"\x03\x03",
            hello_version=b"\x03\x03",
            cipher_suites=b"\x00\x0A",    # TLS_RSA_WITH_3DES_EDE_CBC_SHA
        )
        _send_raw_tcp(payload)
        found = _wait_for_alert("Weak Cipher Suite Detected (3DES-EDE-CBC-SHA)")
        self.assertTrue(found,
            "Alert '3DES' non trovato nel log snort-internal entro il timeout.")

    def test_weak_cipher_deprecated_ja3(self):
        """
        Invia un ClientHello con cipher RSA-AES-128-CBC-SHA (0x00 0x2F),
        tipica di JA3 anomali o tool legacy.
        """
        payload = _make_tls_client_hello(
            record_version=b"\x03\x03",
            hello_version=b"\x03\x03",
            cipher_suites=b"\x00\x2F",    # TLS_RSA_WITH_AES_128_CBC_SHA
        )
        _send_raw_tcp(payload)
        found = _wait_for_alert("Weak Cipher Suite Detected (AES-128-CBC-SHA / JA3 Anomaly)")
        self.assertTrue(found,
            "Alert 'JA3 Deprecated Cipher' non trovato nel log snort-internal entro il timeout.")

    # -----------------------------------------------------------------------
    # mTLS Violation
    # -----------------------------------------------------------------------

    def test_mtls_missing_client_cert(self):
        """
        Simula un messaggio Certificate TLS vuoto (0x0B con payload 00 00 00),
        che indica che il client non ha inviato un certificato durante l'handshake mTLS.
        """
        # Questo payload è un TLS Handshake Certificate message con certificato vuoto
        payload = (
            b"\x16\x03\x03"           # TLS 1.2 record header
            + struct.pack("!H", 7)    # lunghezza record = 7 byte
            + b"\x0B"                 # HandshakeType: Certificate (11 = 0x0B)
            + b"\x00\x00\x03"         # lunghezza handshake = 3
            + b"\x00\x00\x00"         # lista certificati vuota
        )
        _send_raw_tcp(payload)
        found = _wait_for_alert("mTLS Violation Detected (Missing Client Certificate)")
        self.assertTrue(found,
            "Alert 'mTLS Violation' non trovato nel log snort-internal entro il timeout.")

    # -----------------------------------------------------------------------
    # SYN Flood
    # -----------------------------------------------------------------------

    def test_syn_flood(self):
        """
        Invia 35 connessioni TCP SYN verso la porta Envoy in rapida successione
        per superare la soglia di 30 SYN in 2 secondi.
        Nota: ogni connect() invia automaticamente il SYN; chiudiamo subito senza completare l'handshake.
        """
        sockets = []
        try:
            for _ in range(35):
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setblocking(False)
                try:
                    s.connect((TARGET_HOST, TARGET_PORT))
                except BlockingIOError:
                    pass  # normale: SYN inviato, handshake non completato
                sockets.append(s)
                time.sleep(0.02)  # ~35 SYN in ~0.7s: ben sopra soglia (30 in 2s)
        finally:
            for s in sockets:
                try:
                    s.close()
                except Exception:
                    pass

        found = _wait_for_alert("SYN Flood - Volumetric Network Attack Detected")
        self.assertTrue(found,
            "Alert 'SYN Flood' non trovato nel log snort-internal entro il timeout.")


if __name__ == "__main__":
    unittest.main(verbosity=2)
