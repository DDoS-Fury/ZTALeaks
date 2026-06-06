package handler

import (
	"html/template"
	"log"
	"net/http"
)

// HomeHandler gestisce la route della pagina principale HTML
func HomeHandler(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("templates/index.html")
	if err != nil {
		log.Printf("Errore nel parsing del template: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	err = tmpl.Execute(w, nil)
	if err != nil {
		log.Printf("Errore nell'esecuzione del template: %v", err)
	}
}

// MaterialsHandler gestisce la route della pagina dei materiali HTML
func MaterialsHandler(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("templates/materials.html")
	if err != nil {
		log.Printf("Errore nel parsing del template materials: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	err = tmpl.Execute(w, nil)
	if err != nil {
		log.Printf("Errore nell'esecuzione del template materials: %v", err)
	}
}

// ReservedHandler gestisce la route della pagina riservata HTML
func ReservedHandler(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("templates/reserved.html")
	if err != nil {
		log.Printf("Errore nel parsing del template reserved: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	err = tmpl.Execute(w, nil)
	if err != nil {
		log.Printf("Errore nell'esecuzione del template reserved: %v", err)
	}
}

// NotFoundHandler gestisce le richieste a percorsi non esistenti
func NotFoundHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("404 - Percorso non trovato: %s %s [Remote: %s]", r.Method, r.URL.Path, r.Header.Get("x-envoy-external-address"))
	http.Error(w, "404 page not found - ZTALeaks Debug", http.StatusNotFound)
}
