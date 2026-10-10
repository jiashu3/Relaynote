package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"relaynote/internal/api"
	"relaynote/internal/outbox"
	"relaynote/internal/store"
	"strings"
	"testing"
)

func TestCLIRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	db := filepath.Join(dir, "hub.db")
	aFile := filepath.Join(dir, "a.token")
	bFile := filepath.Join(dir, "b.token")
	invoke := func(args ...string) []byte {
		t.Helper()
		var out bytes.Buffer
		if e := run(args, &out); e != nil {
			t.Fatal(e)
		}
		return out.Bytes()
	}
	invoke("--db", db, "provision", "--peer", "A", "--allow", "B", "--out", aFile)
	invoke("--db", db, "provision", "--peer", "B", "--allow", "A", "--out", bFile)
	s, e := store.New(db)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	server := httptest.NewServer(api.New(s))
	defer server.Close()
	node := func(file string, args ...string) []byte {
		return invoke(append([]string{"--url", server.URL, "--token-file", file, "--outbox", filepath.Join(dir, "outbox.db")}, args...)...)
	}
	var m store.Message
	json.Unmarshal(node(aFile, "send", "--to", "B", "--body", "ping", "--client-id", "c1"), &m)
	var inbox struct {
		Messages []store.Message `json:"messages"`
	}
	json.Unmarshal(node(bFile, "claim"), &inbox)
	if len(inbox.Messages) != 1 || inbox.Messages[0].ID != m.ID {
		t.Fatal(inbox)
	}
	node(bFile, "ack", "--id", m.ID, "--receipt="+inbox.Messages[0].Receipt)
	node(bFile, "reply", "--parent", m.ID, "--body", "pong", "--client-id", "r1")
	json.Unmarshal(node(aFile, "claim"), &inbox)
	if len(inbox.Messages) != 1 || inbox.Messages[0].Body != "pong" {
		t.Fatal(inbox)
	}
	var out bytes.Buffer
	if e = run([]string{"--url", server.URL, "--token-file", aFile, "ack", "--id", inbox.Messages[0].ID, "--receipt=-" + strings.Repeat("a", 31)}, &out); e == nil || !strings.Contains(e.Error(), "409") {
		t.Fatalf("leading hyphen should parse and reach server: %v", e)
	}
	if text := string(invoke("version")); !strings.Contains(text, "Ripplelab Limited") {
		t.Fatal(text)
	}
}

func TestOutboxPoisonDoesNotBlockOtherEntries(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "outbox.db")
	tokenFile := filepath.Join(dir, "node.token")
	token, _ := store.NewToken()
	os.WriteFile(tokenFile, []byte(token), 0600)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		if body["client_id"] == "bad" {
			w.WriteHeader(403)
			w.Write([]byte(`{"error":"denied"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":"accepted"}`))
	}))
	defer server.Close()
	box, e := outbox.New(path)
	if e != nil {
		t.Fatal(e)
	}
	bad, e := box.Enqueue(server.URL, token, "/v1/messages", "bad", map[string]string{"client_id": "bad"})
	if e != nil {
		t.Fatal(e)
	}
	_, e = box.Enqueue(server.URL, token, "/v1/messages", "good", map[string]string{"client_id": "good"})
	if e != nil {
		t.Fatal(e)
	}
	box.Close()
	global := []string{"--url", server.URL, "--token-file", tokenFile, "--outbox", path}
	var output bytes.Buffer
	if e = run(append(global, "flush"), &output); e == nil {
		t.Fatal("expected retained-entry error")
	}
	box, e = outbox.New(path)
	if e != nil {
		t.Fatal(e)
	}
	pending, e := box.Pending(server.URL, token)
	if e != nil || len(pending) != 1 || pending[0].Key != bad.Key {
		t.Fatal(pending, e)
	}
	box.Close()
	output.Reset()
	if e = run(append(global, "outbox-list"), &output); e != nil || !strings.Contains(output.String(), bad.Key) {
		t.Fatal(output.String(), e)
	}
	if e = run(append(global, "outbox-drop", "--key", bad.Key), &output); e != nil {
		t.Fatal(e)
	}
}

func TestRemotePlaintextServerRefused(t *testing.T) {
	var out bytes.Buffer
	e := run([]string{"--db", filepath.Join(t.TempDir(), "hub.db"), "serve", "--listen", "0.0.0.0:0"}, &out)
	if e == nil || !strings.Contains(e.Error(), "TLS") {
		t.Fatal(e)
	}
}
