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

var alertRegex = regexp.MustCompile(`^(\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+\[\*\*\]\s+\[(\d+):(\d+):(\d+)\]\s+(.*?)\s+\[\*\*\](?:\s+\[Classification:\s+(.*?)\])?(?:\s+\[Priority:\s+(\d+)\])?(?:\s+\{.*\})?\s+([\d\.]+):(\d+)\s+->\s+([\d\.]+):(\d+)`)

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

// Rate limit: 1 allert ogni 5s per src_ip
const (
	rateInterval = 5 * time.Second
	rateBurst    = 1
)

var (
	rateMu   sync.Mutex
	rateMap  = make(map[string]*rate.Limiter)
	limiterN = rate.Every(rateInterval)
)

func allow(srcIP string) bool {
	rateMu.Lock()
	lim, ok := rateMap[srcIP]
	if !ok {
		lim = rate.NewLimiter(limiterN, rateBurst)
		rateMap[srcIP] = lim
	}
	rateMu.Unlock()
	return lim.Allow()
}

// AlertSender gestisce una singola connessione TCP persistente verso il
// security-orchestrator, con riconnessione automatica e backoff.
type AlertSender struct {
	addr string
	ch   chan SnortAlert
}

func NewAlertSender(addr string, buf int) *AlertSender {
	s := &AlertSender{addr: addr, ch: make(chan SnortAlert, buf)}
	go s.run()
	return s
}

func (s *AlertSender) Send(a SnortAlert) {
	select {
	case s.ch <- a:
	default:
		log.Printf("alert channel full, dropping alert src=%s sid=%s", a.SrcIP, a.RuleSID)
	}
}

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
		log.Printf("connected to %s", s.addr)
		backoff = 1 * time.Second
		if err := s.writeLoop(conn); err != nil {
			log.Printf("write loop terminated: %v, reconnecting", err)
		}
		_ = conn.Close()
	}
}

func (s *AlertSender) writeLoop(conn net.Conn) error {
	enc := json.NewEncoder(conn)
	for a := range s.ch {
		if err := enc.Encode(&a); err != nil {
			return err
		}
	}
	return nil
}

func main() {
	if len(os.Args) < 4 {
		log.Fatalf("Usage: %s <input_file> <output_file> <service_name>", os.Args[0])
	}
	inputFile := os.Args[1]
	outputFile := os.Args[2]
	service := os.Args[3]

	out, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Failed to open output file: %v", err)
	}
	defer out.Close()
	jsonEncoder := json.NewEncoder(out)

	orchestratorAddr := os.Getenv("ORCHESTRATOR_ALERTS_ADDR")
	if orchestratorAddr == "" {
		orchestratorAddr = "security-orchestrator:9000"
	}
	sender := NewAlertSender(orchestratorAddr, 1024)

	cmd := exec.Command("tail", "-F", inputFile)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Fatalf("Failed to get stdout from tail: %v", err)
	}
	if err := cmd.Start(); err != nil {
		log.Fatalf("Failed to start tail command: %v", err)
	}

	reader := bufio.NewReader(stdout)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
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
			if err := jsonEncoder.Encode(alert); err != nil {
				log.Printf("Failed to encode JSON: %v", err)
			}
			if alert.SrcIP != "" && allow(alert.SrcIP) {
				sender.Send(alert)
			}
		} else {
			genAlert := SnortAlert{
				Service:   service,
				Timestamp: time.Now().Format(time.RFC3339),
				Message:   line,
			}
			jsonEncoder.Encode(genAlert)
		}
	}
	cmd.Wait()
}
