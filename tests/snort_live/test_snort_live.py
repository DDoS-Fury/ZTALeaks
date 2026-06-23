import socket
import time
import requests
import urllib3
import threading

# Disabilita i warning per i certificati self-signed
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TARGET_HOST = "localhost"
TARGET_PORT = 8443
HTTP_URL = f"https://{TARGET_HOST}:{TARGET_PORT}"

def trigger_snort_edge():
    print("[*] Triggering Snort Edge - TCP Port Scan (Reconnaissance)")
    # 10 attempts should trigger the rule but stay under the 20/s rate limit
    for _ in range(10):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                s.connect((TARGET_HOST, TARGET_PORT))
        except Exception:
            pass

def trigger_snort_internal():
    print("[*] Triggering Snort Internal - SYN Flood")
    # Il SYN flood (SID 2000006) funziona perché non richiede la direzionalità completa (flow:established).
    # La regola rate limit di nftables scatta a 20/s e "droppa", ma Snort ispeziona in PREROUTING prima del drop!
    # Non è un ban permanente, basta attendere qualche secondo.
    def connect_task():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                s.connect((TARGET_HOST, TARGET_PORT))
        except Exception:
            pass
    
    threads = []
    for _ in range(40):
        t = threading.Thread(target=connect_task)
        t.start()
        threads.append(t)
    
    for t in threads:
        t.join()

def trigger_snort_mid():
    print("[*] Triggering Snort Mid - SQL Injection")
    url = f"{HTTP_URL}/api/v1/personnel?q=UNION+SELECT+*+FROM+users"
    try:
        requests.get(url, verify=False, timeout=3)
    except Exception:
        pass

def make_legitimate_request():
    print("[*] Invio di una richiesta HTTP finale per forzare la valutazione dell'Orchestrator...")
    url = f"{HTTP_URL}/login"  
    try:
        req = requests.get(url, verify=False, timeout=3)
        print(f"[+] Risposta ricevuta (status: {req.status_code})")
    except Exception as e:
        print(f"[-] Errore richiesta: {e}")

if __name__ == "__main__":
    print("=== Inizio fase di inquinamento reputazione (Trigger Snort) ===")
    
    # Eseguiamo gli attacchi in modo progressivo e distanziato per simulare una vera intrusione
    trigger_snort_edge()
    time.sleep(1)
    
    trigger_snort_internal()
    time.sleep(1)
    
    trigger_snort_mid()
    
    print("[+] Attacchi generati. Attendo 3 secondi per l'elaborazione dei log...")
    time.sleep(3)
    
    make_legitimate_request()
    
    print("=== Test Completato ===")
    print(">> Controlla i log dell'orchestrator per verificare il device fingerprinting")
