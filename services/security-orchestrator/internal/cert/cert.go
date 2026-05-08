// =============================================================================
// Cert Parser — estrae info dal client certificate forwarded da Envoy
// Project: ZTALeaks - Security Orchestrator
// =============================================================================
// Envoy con `forward_client_cert_details: APPEND_FORWARD` (step 4) inietta
// l'header `x-forwarded-client-cert` con campi separati da `;`. Esempio:
//   By=spiffe://...;Hash=abcdef;Subject="CN=admin,O=ZTALeaks";URI=...
// Per il tier admission ci basta sapere se il cert è presente. Per il logging
// estraiamo Subject e Hash.
// =============================================================================

package cert

import "strings"

type ClientCert struct {
	Present bool
	Subject string
	Hash    string
}

// Parse legge il valore dell'header. Restituisce Present=false se vuoto.
func Parse(header string) ClientCert {
	if header == "" {
		return ClientCert{Present: false}
	}
	c := ClientCert{Present: true}
	for _, part := range strings.Split(header, ";") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(kv[0]))
		val := strings.Trim(strings.TrimSpace(kv[1]), `"`)
		switch key {
		case "subject":
			c.Subject = val
		case "hash":
			c.Hash = val
		}
	}
	return c
}
