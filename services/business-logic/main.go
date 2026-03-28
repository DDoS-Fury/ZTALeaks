package main

import (
	"log"
	"net/http"
	"os"

	"ztaleaks/business-logic/internal/handler"
)

func main() {
	// Leggi la porta dall'ambiente, o usa un default
	port := os.Getenv("BUSINESS_LOGIC_PORT")
	if port == "" {
		port = "8080"
		log.Println("La variabile BUSINESS_LOGIC_PORT non è impostata. Utilizzo la porta di default: 8080")
	}

	// Inizializza il mux
	mux := http.NewServeMux()

	// Collega i gestori alle rotte
	mux.HandleFunc("/", handler.HomeHandler)

	// Avvia il server
	address := ":" + port
	log.Printf("Avvio del server Business Logic su %s...", address)
	if err := http.ListenAndServe(address, mux); err != nil {
		log.Fatalf("Errore nell'avvio del server: %v", err)
	}
}
