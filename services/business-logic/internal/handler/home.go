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
