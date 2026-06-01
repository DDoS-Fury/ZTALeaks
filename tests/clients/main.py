import ssl
import urllib.request
import urllib.error
import uuid
import time
import socket
import logging

logging.basicConfig(level=logging.INFO, format='%(message)s')

def generate_uuid():
    return str(uuid.uuid4())

def run_request(name, url, req_id, context):
    req = urllib.request.Request(url)
    req.add_header('X-Request-ID', req_id)
    
    try:
        with urllib.request.urlopen(req, context=context, timeout=5) as response:
            status = response.getcode()
            # Read first 100 bytes for truncation
            body = response.read(100).decode('utf-8', errors='ignore')
            logging.info(f"[{name}] Response Status: {status}")
            logging.info(f"[{name}] Response Body (truncated): {body}...")
    except urllib.error.URLError as e:
        logging.error(f"[{name}] Request failed: {e.reason}")
    except Exception as e:
        logging.error(f"[{name}] Request failed: {e}")

def simulate_port_scan(host):
    for port in range(8000, 8015):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.1)
        try:
            s.connect((host, port))
            s.close()
        except (socket.timeout, ConnectionRefusedError, OSError):
            pass
        finally:
            s.close()
    logging.info("[PortScan] Finished sending SYN packets for port scan.")

def simulate_syn_flood(host, port, count=40):
    logging.info(f"[SynFlood] Simulating high request rate on {host}:{port} ({count} requests)")
    for _ in range(count):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.01)
        try:
            s.connect((host, port))
            s.close()
        except Exception:
            pass
        finally:
            s.close()
    logging.info(f"[SynFlood] Finished sending {count} connections.")

def simulate_rapid_requests(host, port, count=100, interval=0.05):
    logging.info(f"[RapidRequests] Sending {count} rapid TCP SYNs to {host}:{port} (interval={interval}s)")
    for i in range(count):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.01)
        try:
            s.connect((host, port))
            s.close()
        except Exception:
            pass
        finally:
            s.close()
        time.sleep(interval)
    logging.info(f"[RapidRequests] Finished rapid SYN sequence.")

def simulate_malformed_requests(host, port, count=10):
    logging.info(f"[MalformedRequests] Sending {count} malformed/incomplete TLS handshakes")
    for _ in range(count):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.1)
            s.connect((host, port))
            s.send(b'\x16\x03\x01\x00\x04JUNK')
            s.close()
        except Exception:
            pass
    logging.info(f"[MalformedRequests] Finished malformed request sequence.")

def main():
    logging.info("Waiting 10 seconds for Envoy to start...")
    time.sleep(10)

    target_url = "https://ztaleaks_envoy:8443/"
    ca_path = "/app/certs/ca.crt"
    cert_path = "/app/certs/client.crt"
    key_path = "/app/certs/client.key"

    # 1. Valid Request (Standard Modern Ciphers)
    valid_req_id = generate_uuid()
    logging.info(f"Starting Valid Request. X-Request-ID: {valid_req_id}")
    ctx_valid = ssl.create_default_context()
    ctx_valid.check_hostname = False
    ctx_valid.verify_mode = ssl.CERT_NONE
    run_request("Valid", target_url, valid_req_id, ctx_valid)

    # 2. Anomalous Request (Restricted/Deprecated Cipher Suite)
    anomalous_req_id = generate_uuid()
    logging.info(f"\nStarting Anomalous Request. X-Request-ID: {anomalous_req_id}")
    ctx_anom = ssl.create_default_context()
    ctx_anom.check_hostname = False
    ctx_anom.verify_mode = ssl.CERT_NONE
    # AES128-SHA is OpenSSL's name for TLS_RSA_WITH_AES_128_CBC_SHA
    ctx_anom.set_ciphers('AES128-SHA')
    ctx_anom.maximum_version = ssl.TLSVersion.TLSv1_2
    run_request("Anomalous", target_url, anomalous_req_id, ctx_anom)

    # 3. Valid Request with real certificate
    real_cert_req_id = generate_uuid()
    logging.info(f"\nStarting real Request. X-Request-ID: {real_cert_req_id}")
    ctx_real = ssl.create_default_context(cafile=ca_path)
    ctx_real.load_cert_chain(certfile=cert_path, keyfile=key_path)
    ctx_real.check_hostname = False # Disabilitato per analogia col codice Go sennò fallirebbe su "ztaleaks_envoy"
    ctx_real.verify_mode = ssl.CERT_REQUIRED
    run_request("RealCert", target_url, real_cert_req_id, ctx_real)

    # 4. Simulate a Port Scan to trigger Snort IDS detection
    port_scan_req_id = generate_uuid()
    logging.info(f"\nStarting Port Scan Simulation. X-Request-ID: {port_scan_req_id}")
    simulate_port_scan("ztaleaks_envoy")

    # 5. Simulate SYN Flood to test nftables rate-limiting
    simulate_syn_flood("ztaleaks_envoy", 8443)

    # 6. Simulate Rapid Requests (high frequency to trigger rate-limiting thresholds)
    simulate_rapid_requests("ztaleaks_envoy", 8443, count=50, interval=0.02)

    # 7. Simulate Malformed TLS Handshakes
    simulate_malformed_requests("ztaleaks_envoy", 8443, count=5)

if __name__ == "__main__":
    main()
