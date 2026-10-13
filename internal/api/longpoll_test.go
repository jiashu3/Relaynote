package api

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"relaynote/internal/store"
	"relaynote/internal/wake"
	"testing"
	"time"
)

func fixtureOpts(t *testing.T, longpoll bool, wakeSvc *wake.Service) (*store.Store, string, string, *httptest.Server) {
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
	h.LongPoll = longpoll
	h.Wake = wakeSvc
	server := httptest.NewServer(h)
	t.Cleanup(server.Close)
	return s, a, b, server
}

type waitResult struct {
	Messages []store.Message `json:"messages"`
	Cursor   uint64          `json:"cursor"`
}

func send(t *testing.T, server *httptest.Server, token, to, clientID string) {
	t.Helper()
	status, data := call(t, server, token, "POST", "/v1/messages",
		[]byte(fmt.Sprintf(`{"to":%q,"body":"hello","client_id":%q}`, to, clientID)))
	if status != 200 {
		t.Fatalf("%d %s", status, data)
	}
}

func wait(t *testing.T, server *httptest.Server, token string, after uint64, timeout string) waitResult {
	t.Helper()
	status, data := call(t, server, token, "GET",
		fmt.Sprintf("/v1/inbox/wait?after=%d&timeout=%s", after, timeout), nil)
	if status != 200 {
		t.Fatalf("%d %s", status, data)
	}
	var out waitResult
	if e := json.Unmarshal(data, &out); e != nil {
		t.Fatal(e)
	}
	return out
}

func TestWaitEndpointsDisabledByDefault(t *testing.T) {
	_, _, b, server := fixture(t) // fixture() sets no P1 options
	for _, path := range []string{"/v1/inbox/wait?after=0&timeout=0.1", "/v1/wake/status"} {
		status, _ := call(t, server, b, "GET", path, nil)
		if status != 404 {
			t.Fatalf("%s: %d, want 404", path, status)
		}
	}
}

func TestWaitReturnsImmediatelyWhenMessagesExist(t *testing.T) {
	_, a, b, server := fixtureOpts(t, true, nil)
	send(t, server, a, "B", "w1")
	start := time.Now()
	out := wait(t, server, b, 0, "30")
	if len(out.Messages) != 1 || out.Cursor == 0 {
		t.Fatalf("unexpected %+v", out)
	}
	if out.Messages[0].Receipt != "" {
		t.Fatal("wait must not lease messages")
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("wait blocked despite pending message")
	}
}

func TestWaitTimesOutEmpty(t *testing.T) {
	_, _, b, server := fixtureOpts(t, true, nil)
	start := time.Now()
	out := wait(t, server, b, 7, "0.3")
	if len(out.Messages) != 0 || out.Cursor != 7 {
		t.Fatalf("timeout must return empty with cursor unchanged: %+v", out)
	}
	if elapsed := time.Since(start); elapsed < 250*time.Millisecond || elapsed > 5*time.Second {
		t.Fatalf("wait did not honor timeout: %v", elapsed)
	}
}

func TestWaitBlocksUntilNewMessage(t *testing.T) {
	_, a, b, server := fixtureOpts(t, true, nil)
	send(t, server, a, "B", "w1")
	base := wait(t, server, b, 0, "30")
	done := make(chan waitResult, 1)
	go func() { done <- wait(t, server, b, base.Cursor, "5") }()
	select {
	case out := <-done:
		t.Fatalf("wait returned early: %+v", out)
	case <-time.After(200 * time.Millisecond):
	}
	send(t, server, a, "B", "w2")
	select {
	case out := <-done:
		if len(out.Messages) != 1 || out.Messages[0].ClientID != "w2" {
			t.Fatalf("unexpected %+v", out)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("wait did not wake on new message")
	}
}

func TestWaitCatchUpAfterDisconnect(t *testing.T) {
	_, a, b, server := fixtureOpts(t, true, nil)
	send(t, server, a, "B", "w1")
	first := wait(t, server, b, 0, "30")
	if len(first.Messages) != 1 {
		t.Fatalf("unexpected %+v", first)
	}
	// Simulate a disconnect: messages arrive while no wait is outstanding.
	send(t, server, a, "B", "w2")
	send(t, server, a, "B", "w3")
	second := wait(t, server, b, first.Cursor, "30")
	if len(second.Messages) != 2 ||
		second.Messages[0].ClientID != "w2" || second.Messages[1].ClientID != "w3" {
		t.Fatalf("reconnect with cursor missed messages: %+v", second)
	}
	if second.Cursor <= first.Cursor {
		t.Fatalf("cursor did not advance: %+v", second)
	}
	third := wait(t, server, b, second.Cursor, "0.2")
	if len(third.Messages) != 0 || third.Cursor != second.Cursor {
		t.Fatalf("no new messages expected: %+v", third)
	}
}

func TestWaitRejectsBadParams(t *testing.T) {
	_, _, b, server := fixtureOpts(t, true, nil)
	for _, path := range []string{
		"/v1/inbox/wait?timeout=-1", "/v1/inbox/wait?timeout=999", "/v1/inbox/wait?timeout=abc",
		"/v1/inbox/wait?after=-1", "/v1/inbox/wait?after=xyz",
	} {
		status, _ := call(t, server, b, "GET", path, nil)
		if status != 400 {
			t.Fatalf("%s: %d, want 400", path, status)
		}
	}
	status, _ := call(t, server, b, "POST", "/v1/inbox/wait", []byte(`{}`))
	if status != 405 {
		t.Fatalf("POST: %d, want 405", status)
	}
}

func TestWakeStatusEndpoint(t *testing.T) {
	svc, e := wake.NewService(wake.Config{Peers: map[string]wake.PeerConfig{"B": {Adapter: "none"}}})
	if e != nil {
		t.Fatal(e)
	}
	_, a, b, server := fixtureOpts(t, false, svc)
	status, data := call(t, server, b, "GET", "/v1/wake/status", nil)
	if status != 200 {
		t.Fatalf("%d %s", status, data)
	}
	var st wake.Status
	if e := json.Unmarshal(data, &st); e != nil {
		t.Fatal(e)
	}
	if st.Peer != "B" || st.Adapter != "none" || st.Breaker != "closed" || st.Last != nil {
		t.Fatalf("unexpected status %s", data)
	}
	// A send to B triggers an asynchronous wake; poll until it lands.
	send(t, server, a, "B", "wk1")
	deadline := time.Now().Add(2 * time.Second)
	for st.Requested == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
		_, data = call(t, server, b, "GET", "/v1/wake/status", nil)
		json.Unmarshal(data, &st)
	}
	if st.Requested != 1 || st.Last == nil || !st.Last.Effective || st.Last.Outcome != "delivered" {
		t.Fatalf("wake not recorded: %s", data)
	}
	// Peers without config are never woken.
	status, data = call(t, server, a, "GET", "/v1/wake/status", nil)
	json.Unmarshal(data, &st)
	if status != 200 || st.Requested != 0 {
		t.Fatalf("unexpected status %d %s", status, data)
	}
}
