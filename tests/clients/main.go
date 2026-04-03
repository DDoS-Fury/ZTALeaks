package main

import (
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

// generateUUID creates a mock UUID string for tracking
func generateUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func main() {
	// Wait for Envoy to be ready
	log.Println("Waiting 10 seconds for Envoy to start...")
	time.Sleep(10 * time.Second)

	targetURL := "https://ztaleaks_envoy:8443/"

	// 1. Valid Request (Standard Modern Ciphers)
	validReqID := generateUUID()
	log.Printf("Starting Valid Request. X-Request-ID: %s\n", validReqID)
	runRequest("Valid", targetURL, validReqID, &tls.Config{
		InsecureSkipVerify: true, // We are testing the network/TLS handshake properties
	})

	// 2. Anomalous Request (Restricted/Deprecated Cipher Suite)
	anomalousReqID := generateUUID()
	log.Printf("\nStarting Anomalous Request. X-Request-ID: %s\n", anomalousReqID)
	runRequest("Anomalous", targetURL, anomalousReqID, &tls.Config{
		InsecureSkipVerify: true,
		CipherSuites: []uint16{
			tls.TLS_RSA_WITH_AES_128_CBC_SHA, // Less secure / identifiable cipher
		},
		MaxVersion: tls.VersionTLS12,
	})
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
