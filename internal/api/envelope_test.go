package api

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"relaynote/internal/store"
	"testing"
)

func envelopeFixture(t *testing.T, enabled bool) (*store.Store, string, string, *httptest.Server) {
	t.Helper()
	s, e := store.New(filepath.Join(t.TempDir(), "private", "hub.db"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	a, _ := store.NewToken()
	b, _ := store.NewToken()
	if e = s.Provision("A", []string{"B"}, a); e != nil {
		t.Fatal(e)
	}
	if e = s.Provision("B", []string{"A"}, b); e != nil {
		t.Fatal(e)
	}
	h := New(s)
	h.Envelope = enabled
	server := httptest.NewServer(h)
	t.Cleanup(server.Close)
	return s, a, b, server
}

func messageFields(t *testing.T, data []byte) map[string]json.RawMessage {
	t.Helper()
	var fields map[string]json.RawMessage
	if e := json.Unmarshal(data, &fields); e != nil {
		t.Fatal(e)
	}
	return fields
}

func TestLegacyBodyEnvelopeParses(t *testing.T) {
	_, a, _, server := envelopeFixture(t, true)
	body := `{"v":1,"kind":"request","conv":"c1","hop":2,"text":"hello"}`
	raw, _ := json.Marshal(map[string]string{"to": "B", "body": body, "client_id": "legacy"})
	status, data := call(t, server, a, "POST", "/v1/messages", raw)
	if status != 200 {
		t.Fatalf("%d %s", status, data)
	}
	var m store.Message
	if e := json.Unmarshal(data, &m); e != nil {
		t.Fatal(e)
	}
	if m.Kind != "request" || m.Conv != "c1" || m.Hop != 2 || m.Body != body {
		t.Fatalf("legacy envelope not mapped to native fields: %+v", m)
	}
}

func TestNativeEnvelopeFieldsWinOverBody(t *testing.T) {
	_, a, _, server := envelopeFixture(t, true)
	body := `{"v":1,"kind":"request","conv":"c1","hop":2,"text":"hello"}`
	raw := []byte(`{"to":"B","body":` + strconvQuote(body) + `,"client_id":"native","kind":"note","hop":5}`)
	status, data := call(t, server, a, "POST", "/v1/messages", raw)
	if status != 200 {
		t.Fatalf("%d %s", status, data)
	}
	var m store.Message
	if e := json.Unmarshal(data, &m); e != nil {
		t.Fatal(e)
	}
	// Native kind/hop win; conv is absent natively so it maps from the body.
	if m.Kind != "note" || m.Hop != 5 || m.Conv != "c1" {
		t.Fatalf("native fields must win over body envelope: %+v", m)
	}
}

func TestEnvelopeDefaultOff(t *testing.T) {
	_, a, _, server := envelopeFixture(t, false)
	// Native envelope fields are rejected as unknown keys.
	raw := []byte(`{"to":"B","body":"hi","client_id":"k","kind":"request"}`)
	if status, data := call(t, server, a, "POST", "/v1/messages", raw); status != 400 {
		t.Fatalf("envelope field accepted while disabled: %d %s", status, data)
	}
	// A legacy body envelope is plain text: accepted but never mapped.
	body := `{"v":1,"kind":"request","conv":"c1","hop":2,"text":"hello"}`
	raw, _ = json.Marshal(map[string]string{"to": "B", "body": body, "client_id": "legacy-off"})
	status, data := call(t, server, a, "POST", "/v1/messages", raw)
	if status != 200 {
		t.Fatalf("%d %s", status, data)
	}
	fields := messageFields(t, data)
	for _, key := range []string{"kind", "conv", "hop"} {
		if _, ok := fields[key]; ok {
			t.Fatalf("envelope field %q leaked while disabled: %s", key, data)
		}
	}
}

func TestV1MessagesWithoutNewFieldsStillWork(t *testing.T) {
	_, a, b, server := envelopeFixture(t, true)
	status, data := call(t, server, a, "POST", "/v1/messages", []byte(`{"to":"B","body":"ping","client_id":"plain"}`))
	if status != 200 {
		t.Fatalf("%d %s", status, data)
	}
	fields := messageFields(t, data)
	for _, key := range []string{"kind", "conv", "hop"} {
		if _, ok := fields[key]; ok {
			t.Fatalf("unset envelope field %q not omitted: %s", key, data)
		}
	}
	status, data = call(t, server, b, "POST", "/v1/inbox/claim", []byte(`{}`))
	if status != 200 {
		t.Fatalf("%d %s", status, data)
	}
	var inbox struct {
		Messages []map[string]json.RawMessage `json:"messages"`
	}
	if e := json.Unmarshal(data, &inbox); e != nil || len(inbox.Messages) != 1 {
		t.Fatalf("%v %s", e, data)
	}
	for _, key := range []string{"kind", "conv", "hop"} {
		if _, ok := inbox.Messages[0][key]; ok {
			t.Fatalf("claimed message gained %q: %s", key, data)
		}
	}
}

func strconvQuote(s string) string {
	encoded, _ := json.Marshal(s)
	return string(encoded)
}
