// =============================================================================
// nftables Log Parser
//
// Reads the ulogd syslogemu log file produced by the nftables NFLOG target,
// parses each line into a structured JSON record, and appends it to an output
// JSONL file consumed by the Splunk Universal Forwarder.
//
// Usage:
//   nftables-parser <input_log_file> <output_jsonl_file>
//
// The parser follows the log file continuously using "tail -F", which handles
// log rotation transparently.
//
// Expected input format (ulogd syslogemu):
//   <Date> <Time> <Host> <Prefix>: IN=... OUT=... MAC=... SRC=... DST=...
// =============================================================================

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

	inputFile  := os.Args[1]
	outputFile := os.Args[2]

	// Open the output file in append mode, creating it if it does not exist.
	out, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Failed to open output file: %v", err)
	}
	defer out.Close()

	// Follow the input file with "tail -F" (survives log rotation).
	cmd    := exec.Command("tail", "-F", inputFile)
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
				// No new data yet; wait briefly and retry.
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

		record := parseLine(line)

		b, err := json.Marshal(record)
		if err != nil {
			log.Printf("Failed to encode JSON record: %v", err)
			continue
		}
		
		timeStr := record["timestamp"].(string)
		outStr := `{"time":"` + timeStr + `",` + string(b[1:])
		out.WriteString(outStr + "\n")
	}

	// Wait for the tail subprocess to exit (should not happen in normal operation).
	cmd.Wait()
}

// parseLine converts a single ulogd syslogemu line into a map suitable for
// JSON serialisation. Key-value pairs separated by "=" are extracted and
// stored with lower-cased keys. The nftables log prefix (e.g. "fw-accept:")
// is mapped to a human-readable "action" and optional "threat" field.
func parseLine(line string) map[string]interface{} {
	record := make(map[string]interface{})
	record["service"]   = "nftables"
	record["timestamp"] = time.Now().Format(time.RFC3339)
	record["raw"]       = line

	parts := strings.Split(line, " ")
	for _, part := range parts {
		if strings.Contains(part, "=") {
			// Key=value pair from the nftables log line
			kv := strings.SplitN(part, "=", 2)
			if len(kv) == 2 {
				record[strings.ToLower(kv[0])] = kv[1]
			}
		} else if strings.HasSuffix(part, ":") {
			// Log prefix token (e.g. "fw-accept:"); derive action and threat.
			prefix := strings.TrimSuffix(part, ":")
			record["prefix"] = prefix

			switch prefix {
			case "fw-accept", "fw-egress-accept":
				record["action"] = "accept"

			case "fw-drop", "fw-input-drop":
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

	return record
}