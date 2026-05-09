//go:build integration

package main

import (
	"context"
	"encoding/json"
	"os"
	"testing"
)

// Integration tests require real binaries inside the Docker image.
// Run with: go test -tags integration ./...
// These tests are excluded from the standard CI run (go test ./...).

func TestRunSubfinder_Real(t *testing.T) {
	findings, err := RunSubfinder(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("RunSubfinder: %v", err)
	}
	if len(findings) == 0 {
		t.Error("expected at least one subdomain finding")
	}
}

func TestRunDnsx_Real(t *testing.T) {
	lines, err := RunDnsx(context.Background(), "google.com")
	if err != nil {
		t.Fatalf("RunDnsx: %v", err)
	}
	if len(lines) == 0 {
		t.Fatal("expected at least one result")
	}
	var row map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &row); err != nil {
		t.Fatalf("first result not valid JSON: %v", err)
	}
	if row["host"] == nil {
		t.Error("host field missing from DNS result")
	}
}

func TestRunHttpx_Real(t *testing.T) {
	lines, err := RunHttpx(context.Background(), "https://example.com")
	if err != nil {
		t.Fatalf("RunHttpx: %v", err)
	}
	if len(lines) == 0 {
		t.Fatal("expected at least one result")
	}
	var row map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &row); err != nil {
		t.Fatalf("first result not valid JSON: %v", err)
	}
	if row["status_code"] == nil {
		t.Error("status_code field missing from HTTP result")
	}
}

func TestLookupGeoip_Real(t *testing.T) {
	if os.Getenv("GEOIP_DB") == "" {
		t.Skip("GEOIP_DB not set; skipping real GeoIP test")
	}
	entries, err := LookupGeoip([]string{"8.8.8.8"})
	if err != nil {
		t.Fatalf("LookupGeoip: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("expected a result for 8.8.8.8")
	}
	if entries[0].Country != "US" {
		t.Errorf("8.8.8.8 country=%q, want US", entries[0].Country)
	}
}
