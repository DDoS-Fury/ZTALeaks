package main

import (
	"log"
	"net/http"
	"os"
)

func main() {
	port := os.Getenv("SECURITY_ORCHESTRATOR_PORT")
	if port == "" {
		port = "8081"
		log.Println("La variabile SECURITY_ORCHESTRATOR_PORT non e' impostata. Utilizzo la porta di default: 8081")
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Security Orchestrator"))
	})

	address := ":" + port
	log.Printf("Avvio del server Security Orchestrator su %s...", address)
	if err := http.ListenAndServe(address, mux); err != nil {
		log.Fatalf("Errore nell'avvio del server: %v", err)
	}
}
