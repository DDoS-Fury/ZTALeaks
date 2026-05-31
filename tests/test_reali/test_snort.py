import socket
import ssl
import time
import requests
import urllib3
import threading

# Disabilita i warning per i certificati self-signed
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TARGET_HOST = "localhost"
TARGET_PORT = 8443
HTTP_URL = f"https://{TARGET_HOST}:{TARGET_PORT}"

def trigger_snort_external():
    print("[*] Triggering Snort Edge (External) - TCP Port Scan (SID: 1000001)")
    # La regola richiede count 5 in 5 secondi dalla stessa sorgente. Eseguiamo 10 connessioni in rapida successione.
    for _ in range(10):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                s.connect((TARGET_HOST, TARGET_PORT))
        except Exception:
            pass
    print("[+] Port scan inviato.")

def trigger_snort_internal_syn_flood():
    print("[*] Triggering Snort Internal - SYN Flood (SID: 2000006)")
    # La regola richiede count 30 in 2 secondi verso la porta Envoy.
    def connect_task():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                s.connect((TARGET_HOST, TARGET_PORT))
        except Exception:
            pass
    
    threads = []
    # Usiamo thread per garantire simultaneità necessaria alla soglia filter target rule
    for _ in range(40):
        t = threading.Thread(target=connect_task)
        t.start()
        threads.append(t)
    
    for t in threads:
        t.join()
        
    print("[+] SYN Flood (Dos Volumetrico) inviato.")

def trigger_snort_internal_legacy_tls():
    print("[*] Triggering Snort Internal - SSLv3 ClientHello (SID: 2000010)")
    # Invio di un pacchetto crudo TLS ClientHello con version SSLv3 (0x03 0x00) e legacy_version (0x03 0x00)
    # in modo da saltare la logica standard ed attivare direttamente la rule raw stream.
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            s.connect((TARGET_HOST, TARGET_PORT))
            client_hello_sslv3 = bytes.fromhex(
                "160301002f0100002b0300" + # handshake type 1, length 43, version 3.0
                "0000000000000000000000000000000000000000000000000000000000000000" + # random
                "00" + # session id len
                "00020004" + # cipher suites (RC4-MD5)
                "0100" # compression methods
            )
            s.sendall(client_hello_sslv3)
    except Exception:
        pass
    print("[+] Legacy TLS handshake attack inviato.")

def trigger_snort_mid_sqli():
    print("[*] Triggering Snort Mid - SQL Injection su ext_authz (SID: 3000001)")
    # Sfruttiamo il TLS proxying. La fetch va tramite Envoy il quale, rimuovendo il TLS,
    # inoltra il payload plaintext per validazione policy all'IP del PDP (Security Orchestrator - TCP 8081).
    url = f"{HTTP_URL}/api/v1/personnel?q=UNION+SELECT+*+FROM+users"
    try:
        requests.get(url, verify=False, timeout=3)
    except Exception as e:
        print(f"[-] Dettaglio (normale avere fail TLS/403): {e}")
    print("[+] Attacco SQLi su API HTTP inviato.")

def trigger_snort_mid_xss():
    print("[*] Triggering Snort Mid - XSS su ext_authz (SID: 3000010)")
    url = f"{HTTP_URL}/api/v1/personnel?username=<script>alert(1)</script>"
    try:
        requests.get(url, verify=False, timeout=3)
    except Exception:
        pass
    print("[+] Attacco XSS su API HTTP inviato.")

if __name__ == "__main__":
    print("=== Inizio simulazione attacchi (Active Enum/Vuln Explotation) ===")
    
    # 1. Edge/External Snort Rules
    trigger_snort_external()
    time.sleep(1)
    
    # 2. Internal Snort Rules
    trigger_snort_internal_syn_flood()
    time.sleep(1)
    trigger_snort_internal_legacy_tls()
    time.sleep(1)
    
    # 3. Mid Snort Rules (Traffico che passa proxy verso authz)
    trigger_snort_mid_sqli()
    trigger_snort_mid_xss()
    
    print("=== Attacchi completati con successo. ===")
    print(">> Ora puoi consultare la dashboard di Splunk cercando: index=main sourcetype=_json")
