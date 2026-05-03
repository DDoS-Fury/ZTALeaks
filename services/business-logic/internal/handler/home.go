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

// LoginHandler gestisce la route della pagina di login HTML
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("templates/login.html")
	if err != nil {
		log.Printf("Errore nel parsing del template login: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	err = tmpl.Execute(w, nil)
	if err != nil {
		log.Printf("Errore nell'esecuzione del template login: %v", err)
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
