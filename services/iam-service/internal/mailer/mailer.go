// =============================================================================
// Mailer Package — SMTP client per consegna OTP via MailHog
// Project: ZTALeaks - Identity Service
// =============================================================================
// In dev/lab usiamo MailHog (no auth, no TLS). I parametri sono caricati da
// env: SMTP_HOST, SMTP_PORT, SMTP_FROM. Una sola operazione esposta: SendOTP.
// =============================================================================

package mailer

import (
	"fmt"
	"net/smtp"
	"os"
)

type SMTPMailer struct {
	host string
	port string
	from string
}

func New() *SMTPMailer {
	return &SMTPMailer{
		host: getenv("SMTP_HOST", "mailhog"),
		port: getenv("SMTP_PORT", "1025"),
		from: getenv("SMTP_FROM", "noreply@ztaleaks.local"),
	}
}

// SendOTP invia un'email HTML con il codice OTP. MailHog accetta connessioni
// SMTP plain senza autenticazione.
func (m *SMTPMailer) SendOTP(to, otp string) error {
	addr := m.host + ":" + m.port
	subject := "ZTALeaks — codice di verifica"
	body := fmt.Sprintf(`<html><body style="font-family: -apple-system, sans-serif; padding: 24px;">
<h2 style="color:#1a1a1a;">Codice di verifica ZTALeaks</h2>
<p>Il tuo codice è:</p>
<p style="font-size: 32px; font-weight: 700; letter-spacing: 8px; padding: 16px; background:#f5f5f5; border-radius:8px; text-align:center;">%s</p>
<p style="color:#666; font-size:14px;">Valido per 5 minuti. Se non hai richiesto un accesso, ignora questa email.</p>
</body></html>`, otp)

	msg := []byte(
		"From: " + m.from + "\r\n" +
			"To: " + to + "\r\n" +
			"Subject: " + subject + "\r\n" +
			"MIME-Version: 1.0\r\n" +
			"Content-Type: text/html; charset=\"UTF-8\"\r\n\r\n" +
			body)

	return smtp.SendMail(addr, nil, m.from, []string{to}, msg)
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
