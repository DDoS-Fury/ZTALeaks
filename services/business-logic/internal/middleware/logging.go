package middleware

import (
	"context"
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

		// Propaga identita' e request-id nel context: i repository li leggono per
		// il logging applicativo e per impostare il `comment` su ogni operazione
		// Mongo (cosi' il profiler/DB registra l'impiegato finale). Senza questa
		// iniezione ctx.Value("user_id") era sempre nil (bug latente).
		ctx := r.Context()
		ctx = context.WithValue(ctx, "user_id", user)
		ctx = context.WithValue(ctx, "req_id", reqID)
		ctx = context.WithValue(ctx, "X-Request-ID", reqID)
		r = r.WithContext(ctx)

		// Wrappa il ResponseWriter per catturare lo status code finale
		rw := &responseWriter{
			ResponseWriter: w,
			statusCode:     0,
		}

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
			slog.String("remote_addr", r.Header.Get("x-envoy-external-address")),
			slog.Int("status_code", rw.statusCode),
			slog.String("duration", duration.String()),
		)
	})
}
