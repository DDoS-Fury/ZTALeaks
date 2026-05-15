package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// alertRegex matcha il formato "fast" di Snort 2.9:
// MM/DD-HH:MM:SS.ffffff [**] [gid:sid:rev] msg [**] [Classification: ...] [Priority: N] {PROTO} src:port -> dst:port
var alertRegex = regexp.MustCompile(`^(\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+\[\*\*\]\s+\[\d+:\d+:\d+\]\s+(.*?)\s+\[\*\*\](?:\s+\[Classification:\s+(.*?)\])?(?:\s+\[Priority:\s+(\d+)\])?(?:\s+\{.*\})?\s+([\d\.]+):(\d+)\s+->\s+([\d\.]+):(\d+)`)

// SnortAlert è la struttura JSON emessa su stdout e salvata sul volume.
type SnortAlert struct {
	Timestamp      string `json:"timestamp"`
	Source         string `json:"source"`
	Message        string `json:"message"`
	Classification string `json:"classification,omitempty"`
	Priority       string `json:"priority,omitempty"`
	SrcIP          string `json:"src_ip,omitempty"`
	SrcPort        string `json:"src_port,omitempty"`
	DstIP          string `json:"dst_ip,omitempty"`
	DstPort        string `json:"dst_port,omitempty"`
}

func main() {
	if len(os.Args) < 3 {
		log.Fatalf("Usage: %s <input_file> <output_file>", os.Args[0])
	}
	inputFile := os.Args[1]
	outputFile := os.Args[2]

	// SOURCE identifica questo snort negli alert JSON (usato da Splunk per distinguere i sensori)
	source := "snort-internal"

	// Apre il file sul volume in append; lo crea se non esiste.
	out, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Failed to open output file: %v", err)
	}
	defer out.Close()

	// bufWriter garantisce un flush esplicito dopo ogni alert, riducendo il rischio
	// di perdita dati in caso di crash e migliorando la latenza verso Splunk.
	bufWriter := bufio.NewWriter(out)

	// Dual-writer: scrive su file (volume) e su stdout (docker logs) in un'unica operazione.
	writeAlert := func(alert SnortAlert) {
		data, err := json.Marshal(alert)
		if err != nil {
			log.Printf("Failed to marshal alert: %v", err)
			return
		}
		line := string(data) + "\n"

		// Scrittura su stdout (visibile con `docker logs`)
		fmt.Print(line)

		// Scrittura sul volume con flush immediato
		if _, err := bufWriter.WriteString(line); err != nil {
			log.Printf("Failed to write to volume file: %v", err)
			return
		}
		if err := bufWriter.Flush(); err != nil {
			log.Printf("Failed to flush to volume file: %v", err)
		}
	}

	// Usa `tail -F` per seguire il file alert di Snort in modo robusto:
	// -F gestisce la rotazione del file (inode change) automaticamente.
	cmd := exec.Command("tail", "-F", inputFile)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Fatalf("Failed to get stdout from tail: %v", err)
	}
	if err := cmd.Start(); err != nil {
		log.Fatalf("Failed to start tail command: %v", err)
	}

	log.Printf("[snort-parser] Started. source=%s input=%s output=%s", source, inputFile, outputFile)

	reader := bufio.NewReader(stdout)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				time.Sleep(200 * time.Millisecond)
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
				Timestamp:      matches[1],
				Source:         source,
				Message:        strings.TrimSpace(matches[2]),
				Classification: strings.TrimSpace(matches[3]),
				Priority:       strings.TrimSpace(matches[4]),
				SrcIP:          strings.TrimSpace(matches[5]),
				SrcPort:        strings.TrimSpace(matches[6]),
				DstIP:          strings.TrimSpace(matches[7]),
				DstPort:        strings.TrimSpace(matches[8]),
			}
			writeAlert(alert)
		} else {
			// Linee non parsabili (es. header di startup Snort) vengono comunque loggiate
			// con timestamp corrente per non perdere contesto.
			writeAlert(SnortAlert{
				Timestamp: time.Now().Format("01/02-15:04:05.000000"),
				Source:    source,
				Message:   line,
			})
		}
	}
	cmd.Wait()
}
