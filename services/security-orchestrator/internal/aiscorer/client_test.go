package aiscorer

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestInfer_NoURL_ReturnsLowConfidence(t *testing.T) {
	c := &Client{url: "", httpClient: http.DefaultClient}
	got := c.Infer(context.Background(), Event{KeySrc: "EMP-001"})
	if got.Confidence != ConfidenceLow || got.Score != 0.99 {
		t.Fatalf("expected {0.99, low}, got %+v", got)
	}
}

func TestInfer_HTTPError_ReturnsLowConfidence(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	c := &Client{url: srv.URL, httpClient: srv.Client()}
	got := c.Infer(context.Background(), Event{KeySrc: "EMP-001"})
	if got.Confidence != ConfidenceLow || got.Score != 0.99 {
		t.Fatalf("expected {0.99, low} on 500, got %+v", got)
	}
}

func TestInfer_HappyPath_ReturnsHighConfidence(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"anomaly_score": 0.42}`))
	}))
	defer srv.Close()
	c := &Client{url: srv.URL, httpClient: srv.Client()}
	got := c.Infer(context.Background(), Event{KeySrc: "EMP-001"})
	if got.Confidence != ConfidenceHigh || got.Score != 0.42 {
		t.Fatalf("expected {0.42, high}, got %+v", got)
	}
}

func TestInfer_MalformedJSON_ReturnsLowConfidence(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`not json`))
	}))
	defer srv.Close()
	c := &Client{url: srv.URL, httpClient: srv.Client()}
	got := c.Infer(context.Background(), Event{KeySrc: "EMP-001"})
	if got.Confidence != ConfidenceLow || got.Score != 0.99 {
		t.Fatalf("expected {0.99, low} on bad JSON, got %+v", got)
	}
}

