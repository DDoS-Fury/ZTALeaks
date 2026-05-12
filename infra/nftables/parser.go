package main

import (
	"bufio"
	"encoding/json"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"
)

func main() {
	if len(os.Args) < 3 {
		log.Fatalf("Usage: %s <input_file> <output_file>", os.Args[0])
	}
	inputFile := os.Args[1]
	outputFile := os.Args[2]

	out, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Failed to open output file: %v", err)
	}
	defer out.Close()
	jsonEncoder := json.NewEncoder(out)

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

		// Simple parsing for ulogd LOGEMU output
		// Formato atteso (syslogemu):
		// <Data> <Ora> <Host> <Str> IN=... OUT=... MAC=... SRC=... DST=...

		record := make(map[string]interface{})
		record["service"] = "nftables"
		record["timestamp"] = time.Now().Format(time.RFC3339)
		record["raw"] = line

		// Estraiamo parti chiave-valore
		parts := strings.Split(line, " ")
		for _, part := range parts {
			if strings.Contains(part, "=") {
				kv := strings.SplitN(part, "=", 2)
				if len(kv) == 2 {
					record[strings.ToLower(kv[0])] = kv[1]
				}
			} else if strings.HasSuffix(part, ":") && !strings.Contains(part, "=") {
				prefix := strings.TrimSuffix(part, ":")
				record["prefix"] = prefix

				switch prefix {
				case "fw-accept":
					record["action"] = "accept"
				case "fw-drop":
					record["action"] = "drop"
				case "fw-syn-flood-drop":
					record["action"] = "drop"
					record["threat"] = "syn_flood"
				case "fw-egress-drop":
					record["action"] = "drop"
					record["threat"] = "unauthorized_egress"
				}
			}
		}

		if err := jsonEncoder.Encode(record); err != nil {
			log.Printf("Failed to encode JSON: %v", err)
		}
	}
	cmd.Wait()
}
