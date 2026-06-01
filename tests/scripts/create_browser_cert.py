import os
import sys

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.serialization import pkcs12
except ImportError:
    print("Errore: la libreria 'cryptography' non è installata.")
    print("Installa la libreria eseguendo: pip install cryptography")
    sys.exit(1)

def main():
    # Definiamo i path relativi dalla cartella in cui eseguirai lo script
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "certs"))
    cert_path = os.path.join(base_dir, "client.crt")
    key_path = os.path.join(base_dir, "client.key")
    p12_path = os.path.join(base_dir, "client.p12")

    if not os.path.exists(cert_path) or not os.path.exists(key_path):
        print(f"Non ho trovato i certificati in {base_dir}.")
        print("Assicurati che client.crt e client.key esistano.")
        sys.exit(1)

    print(f"Leggendo il certificato da: {cert_path}")
    with open(cert_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())

    print(f"Leggendo la chiave privata da: {key_path}")
    with open(key_path, "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None)

    # E' necessario impostare una password per poterlo importare su OS/Browser
    password = b"ztaleaks"
    
    print("Generando il file PKCS#12 (.p12)...")
    p12_data = pkcs12.serialize_key_and_certificates(
        name=b"ZTALeaks Client Certificate",
        key=key,
        cert=cert,
        cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(password)
    )

    with open(p12_path, "wb") as f:
        f.write(p12_data)

    print("\n--- SUCCESSO ---")
    print(f"Certificato per il browser creato: {p12_path}")
    print("Password di importazione: ztaleaks\n")
    print("Per installarlo su Windows / Chrome / Edge:")
    print("1. Fai doppio clic sul file client.p12")
    print("2. Segui la procedura guidata (Mantieni 'Utente Corrente')")
    print("3. Usa la password 'ztaleaks' quando richiesta")
    print("4. Riavvia il browser e visita https://localhost:8443")
    print("   Nota: Il browser dovrebbe chiederti quale certificato usare!")

if __name__ == "__main__":
    main()
