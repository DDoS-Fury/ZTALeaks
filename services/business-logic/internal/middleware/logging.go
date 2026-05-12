package middleware

import (
	"log/slog"
	"net/http"
	"time"
)

// responseWriter è un wrapper per intercettare lo status code della risposta HTTP
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	// Se WriteHeader non è stato chiamato esplicitamente, ma viene inviato il body, assume 200 OK
	if rw.statusCode == 0 {
		rw.statusCode = http.StatusOK
	}
	return rw.ResponseWriter.Write(b)
}

// LoggingMiddleware è il middleware per loggare le richieste HTTP in formato JSON
// Strutturato per la compatibilità con Splunk (Tracciabilità ZTA).
// TODO (Futuro): In seguito, qui verrà gestita l'autenticazione e la verifica del JWT.
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Estrai l'X-Request-ID inserito da Envoy/Orchestrator per l'end-to-end tracing
		reqID := r.Header.Get("X-Request-ID")
		if reqID == "" {
			reqID = "unknown_request"
		}

		user := r.Header.Get("X-Current-User")
		ja3 := r.Header.Get("X-Ja3-Fingerprint")

		// Wrappa il ResponseWriter per catturare lo status code finale
		rw := &responseWriter{
			ResponseWriter: w,
			statusCode:     0,
		}

		// TODO (Futuro): Controllo autenticazione e validazione Token JWT andranno collocati qui.

		// Passa la richiesta al gestore effettivo (ServeMux router o handler sottostante)
		next.ServeHTTP(rw, r)

		// Se lo status non è stato ancora impostato dopo la chiamata, default 200
		if rw.statusCode == 0 {
			rw.statusCode = http.StatusOK
		}

		duration := time.Since(start)

		// Emetti log in JSON strutturato nativo per il forwarding a Splunk
		slog.Info("Request handled",
			slog.String("x_request_id", reqID),
			slog.String("user", user),
			slog.String("ja3_fingerprint", ja3),
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.String("remote_addr", r.RemoteAddr),
			slog.Int("status_code", rw.statusCode),
			slog.String("duration", duration.String()),
		)
	})
}
