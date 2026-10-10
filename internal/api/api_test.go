package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"relaynote/internal/store"
	"testing"
)

func fixture(t *testing.T) (*store.Store, string, string, *httptest.Server) {
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
	server := httptest.NewServer(New(s))
	t.Cleanup(server.Close)
	return s, a, b, server
}
func call(t *testing.T, server *httptest.Server, token, method, path string, body []byte) (int, []byte) {
	t.Helper()
	req, e := http.NewRequest(method, server.URL+path, bytes.NewReader(body))
	if e != nil {
		t.Fatal(e)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	r, e := server.Client().Do(req)
	if e != nil {
		t.Fatal(e)
	}
	defer r.Body.Close()
	data, e := io.ReadAll(r.Body)
	if e != nil {
		t.Fatal(e)
	}
	return r.StatusCode, data
}
func TestRoundTrip(t *testing.T) {
	_, a, b, server := fixture(t)
	status, data := call(t, server, a, "POST", "/v1/messages", []byte(`{"to":"B","body":"ping","client_id":"request"}`))
	if status != 200 {
		t.Fatalf("%d %s", status, data)
	}
	var m store.Message
	if e := json.Unmarshal(data, &m); e != nil {
		t.Fatal(e)
	}
	status, data = call(t, server, b, "POST", "/v1/inbox/claim", []byte(`{}`))
	if status != 200 {
		t.Fatal(status, string(data))
	}
	var inbox struct {
		Messages []store.Message `json:"messages"`
	}
	json.Unmarshal(data, &inbox)
	if len(inbox.Messages) != 1 || inbox.Messages[0].ID != m.ID {
		t.Fatal(string(data))
	}
	receipt := inbox.Messages[0].Receipt
	raw, _ := json.Marshal(map[string]string{"receipt": receipt})
	status, data = call(t, server, b, "POST", "/v1/messages/"+m.ID+"/ack", raw)
	if status != 200 {
		t.Fatal(status, string(data))
	}
	if bytes.Contains(data, []byte(receipt)) {
		t.Fatal("ACK leaked receipt")
	}
	status, data = call(t, server, b, "POST", "/v1/messages/"+m.ID+"/reply", []byte(`{"body":"pong","client_id":"reply"}`))
	if status != 200 {
		t.Fatal(status, string(data))
	}
	var reply store.Message
	json.Unmarshal(data, &reply)
	if reply.ThreadID != m.ThreadID || reply.AgentAwakened != "unverified" {
		t.Fatal(string(data))
	}
	status, data = call(t, server, a, "POST", "/v1/inbox/claim", []byte(`{}`))
	if status != 200 || !bytes.Contains(data, []byte(reply.ID)) {
		t.Fatal(status, string(data))
	}
}
func TestJSONValidation(t *testing.T) {
	_, a, _, server := fixture(t)
	invalid := []string{`[]`, `null`, `1`, `"x"`, `{`, `{} {}`, `{"to":"B","to":"A","body":"x","client_id":"k"}`, `{"to":"B","body":"\ud800","client_id":"k"}`, `{"to":"\ud800","body":"x","client_id":"k"}`, `{"to":"B","body":"x","client_id":"k","ttl":true}`, `{"to":"B","body":"x","client_id":"k","ttl":null}`, `{"to":"B","body":"x","client_id":"k","sender":"C"}`}
	for _, raw := range invalid {
		t.Run(raw, func(t *testing.T) {
			status, data := call(t, server, a, "POST", "/v1/messages", []byte(raw))
			if status != 400 {
				t.Fatal(status, string(data))
			}
		})
	}
	valid := `{"to":"B","body":"\ud83d\ude00","client_id":"emoji"}`
	status, data := call(t, server, a, "POST", "/v1/messages", []byte(valid))
	if status != 200 {
		t.Fatal(status, string(data))
	}
	status, _ = call(t, server, a, "POST", "/v1/messages", bytes.Repeat([]byte("x"), MaxRequest+1))
	if status != 413 {
		t.Fatal(status)
	}
	status, _ = call(t, server, "invalid", "POST", "/v1/inbox/claim", []byte(`{}`))
	if status != 401 {
		t.Fatal(status)
	}
}

func TestUnicodeValidator(t *testing.T) {
	for _, raw := range []string{`{"a":"\ud800"}`, `{"a":"\udc00"}`, `{"a":"\ud800x"}`, `{"a":"\ud800\u0000"}`} {
		if _, e := strictObject([]byte(raw)); e == nil {
			t.Fatal(raw)
		}
	}
	for _, raw := range []string{`{"a":"\ud83d\ude00"}`, `{"a":"\\ud800"}`, `{"a":"中文"}`} {
		if _, e := strictObject([]byte(raw)); e != nil {
			t.Fatal(raw, e)
		}
	}
}

func TestAnyToAnyWithACLIsolation(t *testing.T) {
	s, _, _, server := fixture(t)
	peers := []string{"node-1", "node-2", "node-3", "node-4"}
	tokens := map[string]string{}
	for _, peer := range peers {
		token, e := store.NewToken()
		if e != nil {
			t.Fatal(e)
		}
		tokens[peer] = token
		allowed := []string{}
		for _, other := range peers {
			if peer != other {
				allowed = append(allowed, other)
			}
		}
		if e = s.Provision(peer, allowed, token); e != nil {
			t.Fatal(e)
		}
	}
	for _, sender := range peers {
		for _, recipient := range peers {
			if sender == recipient {
				continue
			}
			payload, _ := json.Marshal(map[string]string{"to": recipient, "body": "synthetic task request", "client_id": sender + "-to-" + recipient})
			code, data := call(t, server, tokens[sender], "POST", "/v1/messages", payload)
			if code != 200 {
				t.Fatalf("%s→%s: %d %s", sender, recipient, code, data)
			}
		}
	}
	inboxes := map[string][]store.Message{}
	for _, peer := range peers {
		code, data := call(t, server, tokens[peer], "POST", "/v1/inbox/claim", []byte(`{}`))
		if code != 200 {
			t.Fatal(code, string(data))
		}
		var inbox struct {
			Messages []store.Message `json:"messages"`
		}
		if e := json.Unmarshal(data, &inbox); e != nil {
			t.Fatal(e)
		}
		if len(inbox.Messages) != 3 {
			t.Fatalf("%s received %d, want3", peer, len(inbox.Messages))
		}
		inboxes[peer] = inbox.Messages
	}
	for peer, messages := range inboxes {
		for _, m := range messages {
			ack, _ := json.Marshal(map[string]string{"receipt": m.Receipt})
			code, data := call(t, server, tokens[peer], "POST", "/v1/messages/"+m.ID+"/ack", ack)
			if code != 200 {
				t.Fatal(code, string(data))
			}
			reply, _ := json.Marshal(map[string]string{"body": "synthetic result", "client_id": "result-" + m.ID})
			code, data = call(t, server, tokens[peer], "POST", "/v1/messages/"+m.ID+"/reply", reply)
			if code != 200 {
				t.Fatal(code, string(data))
			}
		}
	}
	for _, peer := range peers {
		code, data := call(t, server, tokens[peer], "POST", "/v1/inbox/claim", []byte(`{}`))
		if code != 200 {
			t.Fatal(code, string(data))
		}
		var inbox struct {
			Messages []store.Message `json:"messages"`
		}
		json.Unmarshal(data, &inbox)
		if len(inbox.Messages) != 3 {
			t.Fatalf("%s missing results", peer)
		}
		for _, m := range inbox.Messages {
			if m.Body != "synthetic result" || m.ReplyTo == nil || m.AgentAwakened != "unverified" {
				t.Fatal(m)
			}
		}
	}
	if e := s.Manage("node-1", "permissions", []string{"node-2", "node-3"}, ""); e != nil {
		t.Fatal(e)
	}
	code, _ := call(t, server, tokens["node-1"], "POST", "/v1/messages", []byte(`{"to":"node-4","body":"blocked","client_id":"blocked"}`))
	if code != 403 {
		t.Fatal(code)
	}
	code, data := call(t, server, tokens["node-4"], "POST", "/v1/messages", []byte(`{"to":"node-1","body":"reverse still allowed","client_id":"reverse"}`))
	if code != 200 {
		t.Fatal(code, string(data))
	}
}
