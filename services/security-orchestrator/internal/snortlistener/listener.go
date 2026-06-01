package snortlistener

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"time"

	"ztaleaks/security-orchestrator/internal/cache"
)

// ListenAndServe avvia un listener TCP che riceve allert Snort serializzati
// come JSON newline-delimited e li scrive nella cache.
func ListenAndServe(ctx context.Context, addr string, snortCache *cache.SnortCache) error {
	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	slog.Info("snort tcp listener in ascolto", "addr", addr)

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return nil
			}
			slog.Warn("snort listener accept error", "error", err)
			time.Sleep(200 * time.Millisecond)
			continue
		}
		go handleConn(conn, snortCache)
	}
}

func handleConn(conn net.Conn, snortCache *cache.SnortCache) {
	defer conn.Close()
	remote := conn.RemoteAddr().String()
	slog.Info("snort parser connesso", "remote", remote)

	scanner := bufio.NewScanner(conn)
	// alert tipici < 1KB, ma alziamo il buffer per sicurezza
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var alert cache.SnortAlert
		if err := json.Unmarshal(line, &alert); err != nil {
			slog.Warn("snort alert json invalido", "error", err, "remote", remote)
			continue
		}
		if alert.SrcIP == "" {
			continue
		}
		snortCache.SetAlert(alert.SrcIP, alert)
	}
	if err := scanner.Err(); err != nil {
		slog.Warn("snort connessione chiusa con errore", "error", err, "remote", remote)
	} else {
		slog.Info("snort connessione chiusa", "remote", remote)
	}
}
