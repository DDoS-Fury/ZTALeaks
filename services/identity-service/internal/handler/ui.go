package handler

import (
	"html/template"
	"log"
	"net/http"
)

func ServeLoginPage(w http.ResponseWriter, r *http.Request) {
	ensureDeviceCookie(w, r)
	tmpl, err := template.ParseFiles("templates/login.html")
	if err != nil {
		log.Printf("Errore nel parsing del template login: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	_ = tmpl.Execute(w, nil)
}

func ServeRegisterPage(w http.ResponseWriter, r *http.Request) {
	ensureDeviceCookie(w, r)
	tmpl, err := template.ParseFiles("templates/register.html")
	if err != nil {
		log.Printf("Errore nel parsing del template register: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	_ = tmpl.Execute(w, nil)
}
