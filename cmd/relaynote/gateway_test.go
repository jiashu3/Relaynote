package main

import (
	"os"
	"path/filepath"
	"relaynote/internal/store"
	"strings"
	"testing"
)

func TestBuildGatewayFlagValidation(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	s, err := store.New(filepath.Join(dir, "hub.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, _, err := buildGateway(s, "", "", true, nil); err == nil ||
		!strings.Contains(err.Error(), "--oauth-issuer") {
		t.Fatalf("--mcp without issuer: %v", err)
	}
	if _, _, err := buildGateway(s, "https://hub.example.com", "", false, nil); err == nil ||
		!strings.Contains(err.Error(), "--oauth-config") {
		t.Fatalf("issuer without config: %v", err)
	}
	cfgPath := filepath.Join(dir, "oauth.json")
	if err := os.WriteFile(cfgPath, []byte(`{"peer":"dot2","allow_insecure_callbacks":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := buildGateway(s, "https://hub.example.com", cfgPath, true, nil); err == nil ||
		!strings.Contains(err.Error(), "loopback") {
		t.Fatalf("insecure callbacks off-loopback: %v", err)
	}
	if _, _, err := buildGateway(s, "http://127.0.0.1:8787", cfgPath, true, nil); err != nil {
		t.Fatalf("loopback gateway: %v", err)
	}
	if err := os.WriteFile(cfgPath, []byte(`{"peer":"dot2","bogus":1}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := buildGateway(s, "http://127.0.0.1:8787", cfgPath, false, nil); err == nil {
		t.Fatal("unknown config key accepted")
	}
}
