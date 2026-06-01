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
    base_dir = os.path.abspath(os.path.dirname(__file__))
    cert_path = os.path.join(base_dir, "admin.crt")
    key_path = os.path.join(base_dir, "admin.key")
    p12_path = os.path.join(base_dir, "admin.p12")
    pfx_path = os.path.join(base_dir, "admin-apple.pfx")

    if not os.path.exists(cert_path) or not os.path.exists(key_path):
        print(f"Non ho trovato i certificati in {base_dir}.")
        print("Assicurati che esistano.")
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

    print("Generando la copia .pfx per la compatibilità con macOS/iOS...")
    with open(pfx_path, "wb") as f:
        f.write(p12_data)

    print("\n--- SUCCESSO ---")
    print(f"Certificato Windows/Android (.p12) creato: {p12_path}")
    print(f"Certificato Apple macOS/iOS (.pfx) creato: {pfx_path}")
    print("Password di importazione: ztaleaks\n")
    print("Per installarlo su Windows / Chrome / Edge:")
    print("1. Fai doppio clic sul file .p12")
    print("2. Segui la procedura guidata (Mantieni 'Utente Corrente')")
    print("3. Usa la password 'ztaleaks' quando richiesta")
    print("\nPer installarlo su macOS / Safari / iOS:")
    print("1. Fai doppio clic sul file .pfx")
    print("2. Verrà aperto l'Accesso Portachiavi (Mac) o l'installazione profilo (iOS)")
    print("3. Usa la password 'ztaleaks' quando richiesta")
    print("4. Assicurati che diventi 'Fidato'")
    print("\n4. Riavvia il browser e visita https://localhost:8443")
    print("   Nota: Il browser dovrebbe chiederti quale certificato usare!")

if __name__ == "__main__":
    main()
