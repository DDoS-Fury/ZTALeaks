package main

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"time"
)

// generateUUID creates a mock UUID string for tracking
func generateUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// Carica il certificato della CA dal file
func getTrustedPool(caPath string) *x509.CertPool {
	caCert, err := os.ReadFile(caPath)
	if err != nil {
		log.Fatalf("Errore: impossibile leggere il file CA: %v", err)
	}

	// Crea un pool vuoto o usa quello di sistema
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}

	// Aggiunge il certificato della tua CA al pool di fiducia
	if ok := pool.AppendCertsFromPEM(caCert); !ok {
		log.Fatal("Errore: il file CA non è un certificato PEM valido")
	}
	return pool
}

func main() {
	// Wait for Envoy to be ready
	log.Println("Waiting 10 seconds for Envoy to start...")
	time.Sleep(10 * time.Second)

	targetURL := "https://ztaleaks_envoy:8443/"

	caFilePath := "/app/certs/ca.crt"

	clientCrtPath := "/app/certs/client.crt"
	clientKeyPath := "/app/certs/client.key"

	// Caricamento del certificato client

	clientCert, err := tls.LoadX509KeyPair(clientCrtPath, clientKeyPath)
	if err != nil {
		log.Fatalf("Errore caricamento certificato client: %v", err)
	}

	// 1. Valid Request (Standard Modern Ciphers but WITHOUT client cert -> triggers mTLS violation rule in TLS 1.2)
	validReqID := generateUUID()
	log.Printf("Starting Valid Request. X-Request-ID: %s\n", validReqID)
	runRequest("Valid", targetURL, validReqID, &tls.Config{
		InsecureSkipVerify: true,             // We are testing the network/TLS handshake properties
		MaxVersion:         tls.VersionTLS12, // Forziamo TLS 1.2 per rendere visibile l'alert di certificato mancante a Snort
	})

	// 2. Anomalous Request (Restricted/Deprecated Cipher Suite)
	// Questo scatenerà l'alert: ZTA: Unexpected JA3/Deprecated Cipher Detected
	anomalousReqID := generateUUID()
	log.Printf("\nStarting Anomalous Request. X-Request-ID: %s\n", anomalousReqID)
	runRequest("Anomalous", targetURL, anomalousReqID, &tls.Config{
		InsecureSkipVerify: true,
		CipherSuites: []uint16{
			tls.TLS_RSA_WITH_AES_128_CBC_SHA, // Cifra deprecata
		},
		MaxVersion: tls.VersionTLS12,
	})

	// 3. Obsolete TLS Version Test (TLS 1.0)
	// Scatenerà l'alert predefinito: ZTA: Obsolete TLS Version Detected (TLS 1.0)
	obsoleteReqID := generateUUID()
	log.Printf("\nStarting Obsolete Protocol Test (TLS 1.0). X-Request-ID: %s\n", obsoleteReqID)
	runRequest("Obsolete", targetURL, obsoleteReqID, &tls.Config{
		InsecureSkipVerify: true,
		MaxVersion:         tls.VersionTLS10,
	})

	// 4. Volumetric Network Attack: SYN Flood su porta 8443
	log.Printf("\nStarting Volumetric Attack (SYN Flood su Envoy)...\n")
	simulateSYNFlood("ztaleaks_envoy", 8443, 40) // Inviamo 40 SYN in un solo istante al medesimo port

	// 5. Real Certificate Request (con certificato client valido)
	realCertReqID := generateUUID()
	log.Printf("\nStarting real Request. X-Request-ID: %s\n", realCertReqID)
	runRequest("RealCert", targetURL, realCertReqID, &tls.Config{
		RootCAs:            getTrustedPool(caFilePath), // Si fida della tua CA
		InsecureSkipVerify: false,                      // OBBLIGATORIO: ora verifichiamo!
		Certificates:       []tls.Certificate{clientCert},
		ServerName:         "ztaleaks_envoy",
	})

	// 6. Port Scan Simulation (SYN Scan su porte comuni)
	portScanReqID := generateUUID()
	log.Printf("\nStarting Port Scan Simulation. X-Request-ID: %s\n", portScanReqID)
	simulatePortScan("ztaleaks_envoy")

}

func simulatePortScan(host string) {
	// Attempt to connect to 15 target ports very quickly
	// This triggers the Snort threshold rule detecting >5 SYN packets in 5 seconds
	for port := 8000; port < 8015; port++ {
		target := fmt.Sprintf("%s:%d", host, port)
		// We only care about transmitting the SYN packet, so we ignore connection refused errors
		conn, err := net.DialTimeout("tcp", target, 100*time.Millisecond)
		if err == nil {
			conn.Close()
		}
	}
	log.Println("[PortScan] Finished sending SYN packets for port scan.")
}

func simulateSYNFlood(host string, port int, amount int) {
	target := fmt.Sprintf("%s:%d", host, port)

	// Eseguo chiamate parallele massicce simulando un Flood sul target designato
	for i := 0; i < amount; i++ {
		go func() {
			conn, _ := net.DialTimeout("tcp", target, 50*time.Millisecond)
			if conn != nil {
				conn.Close()
			}
		}()
	}
	time.Sleep(2 * time.Second) // Attendiamo per assicurarci che completino e l'alert scatti
	log.Println("[SYN Flood] Finished sending SYN packets.")
}

func runRequest(name, urlStr, reqID string, tlsConfig *tls.Config) {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
		Timeout: 5 * time.Second,
	}

	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		log.Printf("[%s] Failed to create request: %v\n", name, err)
		return
	}

	req.Header.Set("X-Request-ID", reqID)

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[%s] Request failed: %v\n", name, err)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	log.Printf("[%s] Response Status: %s\n", name, resp.Status)
	log.Printf("[%s] Response Body (truncated): %.100s...\n", name, string(body))
}
