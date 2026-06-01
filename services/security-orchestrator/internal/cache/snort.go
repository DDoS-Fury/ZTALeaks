package cache

import (
	"sync"
	"time"
)

// SnortAlert rappresenta i dati dell'allarme in arrivo da Snort
type SnortAlert struct {
	Service        string `json:"service"`
	Timestamp      string `json:"timestamp"`
	RuleGID        string `json:"rule_gid"`
	RuleSID        string `json:"rule_sid"`
	RuleRev        string `json:"rule_rev"`
	Message        string `json:"message"`
	Classification string `json:"classification"`
	Priority       string `json:"priority"`
	SrcIP          string `json:"src_ip"`
	SrcPort        string `json:"src_port"`
	DstIP          string `json:"dst_ip"`
	DstPort        string `json:"dst_port"`
}

// IPAlerts raggruppa tutti gli allarmi recenti per un singolo IP
type IPAlerts struct {
	AlertEdge     *SnortAlert
	AlertMid      *SnortAlert
	AlertInternal *SnortAlert
	Expiry        time.Time
}

// SnortCache gestisce in modo thread-safe lo storage in memoria degli alert
type SnortCache struct {
	mu     sync.RWMutex
	alerts map[string]*IPAlerts
	TTL    time.Duration
}

// NewSnortCache inizializza una nuova cache con il TTL specificato
func NewSnortCache(ttl time.Duration) *SnortCache {
	return &SnortCache{
		alerts: make(map[string]*IPAlerts),
		TTL:    ttl,
	}
}

// SetAlert smista l'allarme nello slot corretto in base al servizio
func (c *SnortCache) SetAlert(ip string, alert SnortAlert) {
	c.mu.Lock()
	defer c.mu.Unlock()

	record, exists := c.alerts[ip]
	if !exists {
		record = &IPAlerts{}
		c.alerts[ip] = record
	}

	// Rinnova la scadenza per tutto il record dell'IP
	record.Expiry = time.Now().Add(c.TTL)

	// Smista in base al campo che identifica la provenienza (adattabile ai nomi effettivi nei docker-compose)
	copyAlert := alert
	switch alert.Service {
	case "snort":
		record.AlertEdge = &copyAlert
	case "snort-mid", "snort_mid":
		record.AlertMid = &copyAlert
	case "snort-internal", "snort_internal":
		record.AlertInternal = &copyAlert
	}
}

// GetAlerts ritorna tutto lo stato associato a quell'IP
func (c *SnortCache) GetAlerts(ip string) (*IPAlerts, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	record, exists := c.alerts[ip]
	if !exists {
		return nil, false
	}

	// Verifica se l'entry è scaduta
	if time.Now().After(record.Expiry) {
		return nil, false
	}

	// Facciamo una copia shallow per non esporre i puntatori interni alla mappa fuori dal lock
	copy := *record
	return &copy, true
}
