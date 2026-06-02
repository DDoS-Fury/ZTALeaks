// =============================================================================
// Snort Alert Parser
//
// Reads Snort "fast" format alerts from a log file (followed with "tail -F"),
// converts each line to a structured JSON record, appends it to an output
// JSONL file, and forwards parsed alerts to the Security Orchestrator over a
// persistent TCP connection.
//
// Usage:
//   snort-parser <input_alert_file> <output_jsonl_file> <service_name>
//
// Environment variables:
//   ORCHESTRATOR_ALERTS_ADDR  - TCP address of the orchestrator alert receiver
//                               (default: "security-orchestrator:9000")
//
// Rate limiting:
//   Alerts forwarded to the orchestrator are rate-limited to 1 per 5 seconds
//   per source IP to prevent alert storms from overwhelming the orchestrator.
//
// Snort "fast" alert format:
//   MM/DD-HH:MM:SS.ffffff [**] [GID:SID:REV] Message [**]
//   [Classification: ...] [Priority: N] {PROTO} SRC_IP:PORT -> DST_IP:PORT
// =============================================================================

package main

import (
	"bufio"
	"encoding/json"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// alertRegex parses a single Snort fast-format alert line.
// Capture groups:
//  1  - timestamp       (MM/DD-HH:MM:SS.ffffff)
//  2  - rule GID
//  3  - rule SID
//  4  - rule revision
//  5  - alert message
//  6  - classification  (optional)
//  7  - priority        (optional)
//  8  - source IP
//  9  - source port
// 10  - destination IP
// 11  - destination port
var alertRegex = regexp.MustCompile(
	`^(\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+\[\*\*\]\s+\[(\d+):(\d+):(\d+)\]\s+(.*?)\s+\[\*\*\]` +
		`(?:\s+\[Classification:\s+(.*?)\])?(?:\s+\[Priority:\s+(\d+)\])?` +
		`(?:\s+\{.*?\})?\s+([\d\.]+):(\d+)\s+->\s+([\d\.]+):(\d+)`,
)

// SnortAlert is the structured representation of a parsed Snort alert line.
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

// =============================================================================
// Per-source IP rate limiter
// Limits forwarded alerts to 1 per rateInterval per source IP.
// =============================================================================

const (
	rateInterval = 5 * time.Second
	rateBurst    = 1
)

var (
	rateMu   sync.Mutex
	rateMap  = make(map[string]*rate.Limiter)
	limiterN = rate.Every(rateInterval)
)

// isAllowed returns true if an alert from the given source IP is within the
// configured rate limit. A new limiter is created on first encounter.
func isAllowed(srcIP string) bool {
	rateMu.Lock()
	lim, ok := rateMap[srcIP]
	if !ok {
		lim = rate.NewLimiter(limiterN, rateBurst)
		rateMap[srcIP] = lim
	}
	rateMu.Unlock()
	return lim.Allow()
}

// =============================================================================
// AlertSender - persistent TCP connection to the Security Orchestrator
//
// Alerts are queued in a buffered channel. A background goroutine maintains
// a single TCP connection to the orchestrator and flushes the channel.
// On connection failure, the goroutine reconnects with exponential backoff
// (capped at 30 seconds).
// =============================================================================

// AlertSender manages a persistent TCP connection and an alert channel.
type AlertSender struct {
	addr string
	ch   chan SnortAlert
}

// NewAlertSender creates a new AlertSender and starts the background worker.
// buf controls the size of the internal alert queue.
func NewAlertSender(addr string, buf int) *AlertSender {
	s := &AlertSender{
		addr: addr,
		ch:   make(chan SnortAlert, buf),
	}
	go s.run()
	return s
}

// Send enqueues an alert for forwarding. If the channel is full, the alert
// is dropped and a warning is logged (backpressure protection).
func (s *AlertSender) Send(a SnortAlert) {
	select {
	case s.ch <- a:
	default:
		log.Printf("alert channel full, dropping alert src=%s sid=%s", a.SrcIP, a.RuleSID)
	}
}

// run is the background connection manager. It dials the orchestrator and
// calls writeLoop to drain the alert channel. On any error it closes the
// connection and retries with exponential backoff.
func (s *AlertSender) run() {
	backoff := 1 * time.Second

	for {
		conn, err := net.DialTimeout("tcp", s.addr, 5*time.Second)
		if err != nil {
			log.Printf("dial %s failed: %v (retry in %v)", s.addr, err, backoff)
			time.Sleep(backoff)
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}

		log.Printf("connected to orchestrator at %s", s.addr)
		backoff = 1 * time.Second

		if err := s.writeLoop(conn); err != nil {
			log.Printf("write loop terminated: %v, reconnecting", err)
		}
		conn.Close()
	}
}

// writeLoop reads alerts from the channel and encodes them as newline-delimited
// JSON onto the connection. It returns on the first encode error.
func (s *AlertSender) writeLoop(conn net.Conn) error {
	enc := json.NewEncoder(conn)
	for a := range s.ch {
		if err := enc.Encode(&a); err != nil {
			return err
		}
	}
	return nil
}

// =============================================================================
// main
// =============================================================================

func main() {
	if len(os.Args) < 4 {
		log.Fatalf("Usage: %s <input_file> <output_file> <service_name>", os.Args[0])
	}

	inputFile  := os.Args[1]
	outputFile := os.Args[2]
	service    := os.Args[3]

	// Open the output JSONL file in append mode.
	out, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Failed to open output file: %v", err)
	}
	defer out.Close()

	jsonEncoder := json.NewEncoder(out)

	// Resolve the orchestrator alert receiver address.
	orchestratorAddr := os.Getenv("ORCHESTRATOR_ALERTS_ADDR")
	if orchestratorAddr == "" {
		orchestratorAddr = "security-orchestrator:9000"
	}

	sender := NewAlertSender(orchestratorAddr, 1024)

	// Follow the Snort alert file with "tail -F" (handles log rotation).
	cmd := exec.Command("tail", "-F", inputFile)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Fatalf("Failed to get stdout pipe from tail: %v", err)
	}
	if err := cmd.Start(); err != nil {
		log.Fatalf("Failed to start tail command: %v", err)
	}

	reader := bufio.NewReader(stdout)

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				// No new data; wait briefly before retrying.
				time.Sleep(1 * time.Second)
				continue
			}
			log.Printf("Reader error: %v", err)
			break
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		matches := alertRegex.FindStringSubmatch(line)
		if len(matches) > 0 {
			// Successfully parsed a structured Snort alert line.
			alert := SnortAlert{
				Service:        service,
				Timestamp:      matches[1],
				RuleGID:        matches[2],
				RuleSID:        matches[3],
				RuleRev:        matches[4],
				Message:        strings.TrimSpace(matches[5]),
				Classification: strings.TrimSpace(matches[6]),
				Priority:       strings.TrimSpace(matches[7]),
				SrcIP:          strings.TrimSpace(matches[8]),
				SrcPort:        strings.TrimSpace(matches[9]),
				DstIP:          strings.TrimSpace(matches[10]),
				DstPort:        strings.TrimSpace(matches[11]),
			}

			// Write the structured alert to the JSONL file.
			if err := jsonEncoder.Encode(alert); err != nil {
				log.Printf("Failed to encode alert to JSON: %v", err)
			}

			// Forward to the orchestrator, subject to per-source rate limiting.
			if alert.SrcIP != "" && isAllowed(alert.SrcIP) {
				sender.Send(alert)
			}
		} else {
			// Line did not match the expected format; store it as a raw record.
			genAlert := SnortAlert{
				Service:   service,
				Timestamp: time.Now().Format(time.RFC3339),
				Message:   line,
			}
			if err := jsonEncoder.Encode(genAlert); err != nil {
				log.Printf("Failed to encode raw alert to JSON: %v", err)
			}
		}
	}

	cmd.Wait()
}
