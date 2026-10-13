package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"relaynote/internal/events"
	"relaynote/internal/store"
	"relaynote/internal/wake"
	"sync"
	"testing"
)

// TestEventSinkWiring checks that an mcp-event wake adapter publishes a
// signed message.created callback through the durable events outbox.
func TestEventSinkWiring(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	s, err := store.New(filepath.Join(dir, "hub.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	tokA, _ := store.NewToken()
	tokB, _ := store.NewToken()
	if err := s.Provision("alice", []string{"dot2"}, tokA); err != nil {
		t.Fatal(err)
	}
	if err := s.Provision("dot2", []string{"alice"}, tokB); err != nil {
		t.Fatal(err)
	}

	// Fake MCP client callback receiver with a challenge echo.
	secretBytes := make([]byte, 32)
	for i := range secretBytes {
		secretBytes[i] = byte(i + 1)
	}
	secret := "whsec_" + base64.StdEncoding.EncodeToString(secretBytes)
	var mu sync.Mutex
	var deliveries []string
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf, _ := io.ReadAll(r.Body)
		var payload struct {
			Type      string `json:"type"`
			Challenge string `json:"challenge"`
		}
		_ = json.Unmarshal(buf, &payload)
		w.Header().Set("Content-Type", "application/json")
		if payload.Type == "verification" {
			_ = json.NewEncoder(w).Encode(map[string]string{"challenge": payload.Challenge})
			return
		}
		mu.Lock()
		deliveries = append(deliveries, string(buf))
		mu.Unlock()
	}))
	defer receiver.Close()

	ev := events.New(s.DB(), &events.SafeHTTP{AllowInsecure: true})
	if _, err := ev.Subscribe("dot2", map[string]any{
		"name":     "message.created",
		"delivery": map[string]any{"mode": "webhook", "url": receiver.URL + "/cb", "secret": secret},
	}); err != nil {
		t.Fatal(err)
	}

	cfg := wake.Config{Peers: map[string]wake.PeerConfig{"dot2": {Adapter: "mcp-event", Preview: true}}}
	wakeSvc, err := wake.NewService(cfg)
	if err != nil {
		t.Fatal(err)
	}
	wireEventSinks(wakeSvc, cfg, ev)

	// A message to dot2 triggers an effective wake -> published event -> delivery.
	d := wakeSvc.Wake(context.Background(), "dot2", wake.Notice{
		ID: "m-1", Kind: "chat", From: "alice", Conv: "c-1", Preview: "hello"})
	if !d.Effective || d.Outcome != "delivered" {
		t.Fatalf("wake: %+v", d)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(deliveries) != 1 {
		t.Fatalf("deliveries: %d", len(deliveries))
	}
	var evt map[string]any
	if err := json.Unmarshal([]byte(deliveries[0]), &evt); err != nil {
		t.Fatal(err)
	}
	data, _ := evt["data"].(map[string]any)
	if evt["name"] != "message.created" || data["message_id"] != "m-1" || data["from"] != "alice" ||
		data["kind"] != "chat" || data["reply_allowed"] != true || data["preview"] != "hello" {
		t.Fatalf("event: %s", deliveries[0])
	}
}
