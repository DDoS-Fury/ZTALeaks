package aiscorer

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEvaluate_NoURL_ReturnsLowConfidence(t *testing.T) {
	c := &Client{url: "", httpClient: http.DefaultClient}
	got := c.Evaluate(context.Background(), Features{UserID: "EMP-001"})
	if got.Confidence != ConfidenceLow || got.Score != 0 {
		t.Fatalf("expected {0, low}, got %+v", got)
	}
}

func TestEvaluate_HTTPError_ReturnsLowConfidence(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	c := &Client{url: srv.URL, httpClient: srv.Client()}
	got := c.Evaluate(context.Background(), Features{UserID: "EMP-001"})
	if got.Confidence != ConfidenceLow {
		t.Fatalf("expected low confidence on 500, got %+v", got)
	}
}

func TestEvaluate_HappyPath_ReturnsHighConfidence(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"score": 0.42}`))
	}))
	defer srv.Close()
	c := &Client{url: srv.URL, httpClient: srv.Client()}
	got := c.Evaluate(context.Background(), Features{UserID: "EMP-001"})
	if got.Confidence != ConfidenceHigh || got.Score != 0.42 {
		t.Fatalf("expected {0.42, high}, got %+v", got)
	}
}

func TestEvaluate_MalformedJSON_ReturnsLowConfidence(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`not json`))
	}))
	defer srv.Close()
	c := &Client{url: srv.URL, httpClient: srv.Client()}
	got := c.Evaluate(context.Background(), Features{UserID: "EMP-001"})
	if got.Confidence != ConfidenceLow {
		t.Fatalf("expected low confidence on bad JSON, got %+v", got)
	}
}
