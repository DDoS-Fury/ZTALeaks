package main

import (
	"crypto/tls"
	"encoding/json"
	"html/template"
	"io"
	"log"
	"net/http"
	"time"
)

type DashboardData struct {
	Personnel []map[string]interface{}
	Reactor   []map[string]interface{}
	Zones     []map[string]interface{}
}

func fetchAPI(client *http.Client, url string) ([]map[string]interface{}, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	// ZTALeaks architecture requirement
	req.Header.Set("X-Request-ID", "dashboard-app-fetch")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var rawData interface{}
	if err := json.Unmarshal(body, &rawData); err != nil {
		return nil, err
	}

	var results []map[string]interface{}
	if slice, ok := rawData.([]interface{}); ok {
		for _, item := range slice {
			if m, ok := item.(map[string]interface{}); ok {
				results = append(results, m)
			}
		}
	} else if m, ok := rawData.(map[string]interface{}); ok {
		results = append(results, m)
	}

	return results, nil
}

func main() {
	// The test client has access to test certificates mounted in /certs
	cert, err := tls.LoadX509KeyPair("/certs/client.crt", "/certs/client.key")
	if err != nil {
		log.Fatalf("Failed to load client certificates: %v", err)
	}

	// Disable strict verification for local test composition
	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true,
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	tmpl := template.Must(template.ParseFiles("index.html"))

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		personnel, _ := fetchAPI(client, "https://firewall:8443/api/v1/personnel")
		reactor, _ := fetchAPI(client, "https://firewall:8443/api/v1/reactor-parameters")
		zones, _ := fetchAPI(client, "https://firewall:8443/api/v1/zones")

		data := DashboardData{
			Personnel: personnel,
			Reactor:   reactor,
			Zones:     zones,
		}

		if err := tmpl.Execute(w, data); err != nil {
			http.Error(w, "Failed to render dashboard", http.StatusInternalServerError)
		}
	})

	log.Println("Dashboard app listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
