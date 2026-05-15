"""
tests/snort/test_snort_mid.py

Test suite per gli alert di snort-mid (traffico Envoy -> Security Orchestrator).

Snort-mid monitora le chiamate HTTP (chiare) che Envoy invia al Security
Orchestrator tramite ext_authz (porta 8081). Il modo più efficace per
triggerare questi alert sul sistema live è inviare richieste TLS a Envoy
(porta 8443) che contengano payload SQLi/XSS: Envoy le decodifica e le
inolta in chiaro all'orchestratore, dove snort-mid le intercetta.

Prerequisiti:
  - Stack ZTALeaks avviato: docker compose -f deployments/docker/docker-compose.yaml up -d
  - Certificati presenti in ./certs/ (ca.crt, client.crt, client.key)
  - pip install requests urllib3

Esecuzione:
  python -m pytest tests/snort/test_snort_mid.py -v
  oppure
  python tests/snort/test_snort_mid.py
"""

import os
import time
import subprocess
import unittest
import urllib3

# Disabilita i warning SSL per i test (Envoy usa cert self-signed)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    import requests
except ImportError:
    print("Errore: pip install requests urllib3")
    raise

# ---------------------------------------------------------------------------
# Configurazione
# ---------------------------------------------------------------------------
ENVOY_HOST  = "localhost"
ENVOY_PORT  = int(os.environ.get("ENVOY_PORT", 8443))
ENVOY_URL   = f"https://{ENVOY_HOST}:{ENVOY_PORT}"

CERTS_DIR   = os.path.join(os.path.dirname(__file__), "..", "..", "certs")
CA_CERT     = os.path.join(CERTS_DIR, "ca.crt")
CLIENT_CERT = os.path.join(CERTS_DIR, "client.crt")
CLIENT_KEY  = os.path.join(CERTS_DIR, "client.key")

LOG_POLL_TIMEOUT  = 20      # secondi massimi di attesa per un alert
LOG_POLL_INTERVAL = 0.5

SNORT_MID_CONTAINER   = "ztaleaks_snort_mid"
LOG_PATH_IN_CONTAINER = "/var/log/ztaleaks/snort-mid/alert_json.txt"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_log_tail(n_lines: int = 60) -> str:
    """Legge le ultime n_lines dal file di log snort-mid dentro Docker."""
    result = subprocess.run(
        ["docker", "exec", SNORT_MID_CONTAINER,
         "tail", f"-n{n_lines}", LOG_PATH_IN_CONTAINER],
        capture_output=True, text=True
    )
    return result.stdout


def _wait_for_alert(keyword: str, timeout: float = LOG_POLL_TIMEOUT) -> bool:
    """Polling del log fino a trovare keyword o scadere il timeout."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if keyword in _get_log_tail():
            return True
        time.sleep(LOG_POLL_INTERVAL)
    return False


def _send_request(path: str, method: str = "GET",
                  params: dict = None, data: str = None,
                  headers: dict = None) -> None:
    """
    Invia una richiesta HTTPS a Envoy (che la inoltrerà all'orchestratore in HTTP).
    Usa i certificati mTLS se disponibili, altrimenti va senza.
    Ignora errori di risposta: ci interessa solo che il payload arrivi a snort-mid.
    """
    cert = None
    if os.path.exists(CLIENT_CERT) and os.path.exists(CLIENT_KEY):
        cert = (CLIENT_CERT, CLIENT_KEY)

    verify = CA_CERT if os.path.exists(CA_CERT) else False

    try:
        requests.request(
            method=method,
            url=f"{ENVOY_URL}{path}",
            params=params,
            data=data,
            headers=headers or {},
            cert=cert,
            verify=verify,
            timeout=5,
        )
    except requests.exceptions.RequestException:
        # Ignoriamo errori di risposta (401, 403, timeout, reset):
        # il payload è già arrivato a snort-mid prima che Envoy rispondesse.
        pass


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

class TestSnortMidAlerts(unittest.TestCase):
    """
    Ogni test invia una richiesta HTTPS a Envoy con un payload malevolo.
    Envoy decodifica TLS e inoltra la richiesta HTTP in chiaro al Security
    Orchestrator sulla porta 8081, dove snort-mid intercetta il payload.
    """

    # -----------------------------------------------------------------------
    # SQL Injection
    # -----------------------------------------------------------------------

    def test_sqli_union_select(self):
        """Invia una query string con UNION SELECT (SQL Injection in-band classico)."""
        _send_request(
            "/api/v1/items",
            params={"id": "1 UNION SELECT username,password FROM users--"}
        )
        found = _wait_for_alert("SQL Injection Detected (UNION SELECT)")
        self.assertTrue(found,
            "Alert 'SQLi UNION SELECT' non trovato nel log snort-mid entro il timeout.")

    def test_sqli_or_bypass(self):
        """Invia un body con OR 1=1 (SQL Injection per bypass autenticazione)."""
        _send_request(
            "/api/v1/auth/login",
            method="POST",
            data="username=admin'OR 1=1--&password=x",
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        found = _wait_for_alert("SQL Injection Detected (OR-based Auth Bypass)")
        self.assertTrue(found,
            "Alert 'SQLi OR bypass' non trovato nel log snort-mid entro il timeout.")

    def test_sqli_drop_table(self):
        """Invia un payload con DROP TABLE (SQL Injection distruttiva)."""
        _send_request(
            "/api/v1/items",
            method="POST",
            data='{"query": "DROP TABLE users"}',
            headers={"Content-Type": "application/json"}
        )
        found = _wait_for_alert("SQL Injection Detected (DROP statement)")
        self.assertTrue(found,
            "Alert 'SQLi DROP TABLE' non trovato nel log snort-mid entro il timeout.")

    def test_sqli_comment(self):
        """Invia un payload con commento SQL (--) per troncare la query."""
        _send_request(
            "/api/v1/items",
            params={"name": "test'--"}
        )
        found = _wait_for_alert("SQL Injection Detected (SQL Comment --)")
        self.assertTrue(found,
            "Alert 'SQLi SQL Comment' non trovato nel log snort-mid entro il timeout.")

    def test_sqli_stacked_queries(self):
        """Invia un payload con stacked queries (;) per eseguire comandi multipli."""
        _send_request(
            "/api/v1/items",
            params={"id": "1'; DROP TABLE sessions; --"}
        )
        found = _wait_for_alert("SQL Injection Detected (Stacked Queries)")
        self.assertTrue(found,
            "Alert 'SQLi Stacked Queries' non trovato nel log snort-mid entro il timeout.")

    # -----------------------------------------------------------------------
    # Cross-Site Scripting (XSS)
    # -----------------------------------------------------------------------

    def test_xss_script_tag(self):
        """Invia un payload con tag <script> (XSS classico)."""
        _send_request(
            "/api/v1/items",
            params={"name": "<script>alert('xss')</script>"}
        )
        found = _wait_for_alert("XSS Detected (<script> tag)")
        self.assertTrue(found,
            "Alert 'XSS script tag' non trovato nel log snort-mid entro il timeout.")

    def test_xss_javascript_uri(self):
        """Invia un payload con javascript: URI (XSS via href/src)."""
        _send_request(
            "/api/v1/items",
            params={"url": "javascript:alert(document.cookie)"}
        )
        found = _wait_for_alert("XSS Detected (javascript: URI)")
        self.assertTrue(found,
            "Alert 'XSS javascript: URI' non trovato nel log snort-mid entro il timeout.")

    def test_xss_onerror_handler(self):
        """Invia un payload con onerror= (XSS via event handler su tag img)."""
        _send_request(
            "/api/v1/items",
            params={"html": '<img src=x onerror=alert(1)>'}
        )
        found = _wait_for_alert("XSS Detected (onerror event handler)")
        self.assertTrue(found,
            "Alert 'XSS onerror' non trovato nel log snort-mid entro il timeout.")

    def test_xss_onload_handler(self):
        """Invia un payload con onload= (XSS via event handler su body/iframe)."""
        _send_request(
            "/api/v1/items",
            params={"html": '<body onload=alert(1)>'}
        )
        found = _wait_for_alert("XSS Detected (onload event handler)")
        self.assertTrue(found,
            "Alert 'XSS onload' non trovato nel log snort-mid entro il timeout.")


if __name__ == "__main__":
    unittest.main(verbosity=2)
