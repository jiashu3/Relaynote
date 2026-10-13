package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"relaynote/internal/api"
	"relaynote/internal/store"
	"relaynote/internal/wake"
	"strings"
	"testing"
)

func onboardDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func invokeOnboard(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	err := run(args, &out)
	return out.String(), err
}

// TestInitConnectSnippet covers the <=5-command onboarding flow: hub init,
// then a webhook peer and a poll peer, and the paste-ready snippets.
func TestInitConnectSnippet(t *testing.T) {
	dir := onboardDir(t)
	db := filepath.Join(dir, "hub.db")

	// Command 1: hub init.
	initOut, err := invokeOnboard(t, "hub", "init", "--dir", dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"hub.db", "admin token", "tls-cert", "connect --peer", "doctor --peer"} {
		if !strings.Contains(initOut, want) {
			t.Fatalf("init output missing %q:\n%s", want, initOut)
		}
	}
	if _, err := invokeOnboard(t, "hub", "init", "--dir", dir); err == nil || !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("second init must refuse to overwrite: %v", err)
	}

	// Command 2: connect a webhook peer (platform alias cursor).
	hookHits := 0
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hookHits++
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Write([]byte(`{"ok":true}`))
	}))
	defer hook.Close()
	snippet, err := invokeOnboard(t, "--db", db, "connect", "--peer", "W", "--platform", "cursor",
		"--allow", "admin", "--webhook-url", hook.URL)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(snippet, hook.URL) || !strings.Contains(snippet, "X-Relaynote-Signature") {
		t.Fatalf("webhook snippet must contain URL and signature key note:\n%s", snippet)
	}

	// Command 3: connect a poll peer (platform alias cue).
	pollSnippet, err := invokeOnboard(t, "--db", db, "connect", "--peer", "C", "--platform", "cue", "--allow", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(pollSnippet, "/v1/inbox/wait") || !strings.Contains(pollSnippet, "Bearer") {
		t.Fatalf("poll snippet must contain the long-poll URL and token:\n%s", pollSnippet)
	}

	// Both snippets carry the 4-verb prompt fragment within the size budget.
	for _, s := range []string{snippet, pollSnippet} {
		for _, verb := range []string{"inbox", "reply", "send", "status"} {
			if !strings.Contains(s, verb) {
				t.Fatalf("snippet missing verb %q:\n%s", verb, s)
			}
		}
	}
	prompt, err := renderPrompt(snippetData{Base: "http://127.0.0.1:8787", TokenFile: "peer.token"})
	if err != nil {
		t.Fatal(err)
	}
	if budget := len(prompt) / 4; budget > 300 {
		t.Fatalf("prompt fragment over budget: ~%d tokens", budget)
	}

	// The wake config now holds both peers' entries.
	cfg, err := wake.LoadConfig(filepath.Join(dir, "wake.json"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Peers["W"].Adapter != "webhook" || cfg.Peers["W"].WebhookURL != hook.URL || cfg.Peers["W"].HMACSecret == "" {
		t.Fatalf("webhook wake entry: %+v", cfg.Peers["W"])
	}
	if cfg.Peers["C"].Adapter != "poll" {
		t.Fatalf("poll wake entry: %+v", cfg.Peers["C"])
	}

	// Command 4/5: doctor passes for both peers when healthy.
	out, err := invokeOnboard(t, "--db", db, "doctor", "--peer", "W")
	if err != nil {
		t.Fatalf("healthy webhook doctor must pass: %v\n%s", err, out)
	}
	if !strings.Contains(out, "OK token") || !strings.Contains(out, "OK acl") || !strings.Contains(out, "OK adapter") {
		t.Fatalf("doctor output:\n%s", out)
	}
	if hookHits == 0 {
		t.Fatal("doctor never probed the webhook")
	}
	out, err = invokeOnboard(t, "--db", db, "doctor", "--peer", "C")
	if err != nil || !strings.Contains(out, "OK adapter") || !strings.Contains(out, "adapter poll") {
		t.Fatalf("poll doctor: %v\n%s", err, out)
	}
}

// TestHubURLConfig covers the hub URL resolution order for connect snippets:
// connect --url beats an explicit global --url beats RELAYNOTE_URL beats the
// URL recorded by hub init --url beats the built-in default.
func TestHubURLConfig(t *testing.T) {
	dir := onboardDir(t)
	db := filepath.Join(dir, "hub.db")
	out, err := invokeOnboard(t, "hub", "init", "--dir", dir, "--url", "https://hub.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "https://hub.example.com") {
		t.Fatalf("init must echo the recorded URL:\n%s", out)
	}
	snippet, err := invokeOnboard(t, "--db", db, "connect", "--peer", "P", "--platform", "poll")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(snippet, "https://hub.example.com/v1/inbox/wait") {
		t.Fatalf("snippet must use the URL recorded by hub init:\n%s", snippet)
	}
	snippet, err = invokeOnboard(t, "--db", db, "--url", "https://global.example.com",
		"connect", "--peer", "Q", "--platform", "poll")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(snippet, "https://global.example.com/v1/inbox/wait") {
		t.Fatalf("explicit global --url must beat the recorded URL:\n%s", snippet)
	}
	t.Setenv("RELAYNOTE_URL", "https://env.example.com")
	snippet, err = invokeOnboard(t, "--db", db, "connect", "--peer", "R", "--platform", "poll")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(snippet, "https://env.example.com/v1/inbox/wait") {
		t.Fatalf("RELAYNOTE_URL must beat the recorded URL:\n%s", snippet)
	}
	snippet, err = invokeOnboard(t, "--db", db, "connect", "--peer", "S", "--platform", "poll",
		"--url", "https://flag.example.com/")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(snippet, "https://flag.example.com/v1/inbox/wait") {
		t.Fatalf("connect --url must win:\n%s", snippet)
	}
}

// TestDoctorFailures reports a missing token, a missing ACL edge and an
// unreachable adapter as three separate FAILs.
func TestDoctorFailures(t *testing.T) {
	dir := onboardDir(t)
	db := filepath.Join(dir, "hub.db")
	if _, err := invokeOnboard(t, "hub", "init", "--dir", dir); err != nil {
		t.Fatal(err)
	}

	// Missing token: peer never connected.
	out, err := invokeOnboard(t, "--db", db, "doctor", "--peer", "ghost")
	if err == nil || !strings.Contains(out, "FAIL token") {
		t.Fatalf("missing token: %v\n%s", err, out)
	}

	// Missing ACL edge: peer exists but the edge does not.
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer hook.Close()
	if _, err := invokeOnboard(t, "--db", db, "connect", "--peer", "W", "--platform", "webhook",
		"--allow", "admin", "--webhook-url", hook.URL); err != nil {
		t.Fatal(err)
	}
	out, err = invokeOnboard(t, "--db", db, "doctor", "--peer", "W", "--allow", "nobody")
	if err == nil || !strings.Contains(out, "FAIL acl: missing edge(s): nobody") {
		t.Fatalf("missing ACL edge: %v\n%s", err, out)
	}

	// Unreachable adapter: webhook endpoint is gone.
	hook.Close()
	out, err = invokeOnboard(t, "--db", db, "doctor", "--peer", "W")
	if err == nil || !strings.Contains(out, "FAIL adapter") || !strings.Contains(out, "OK token") {
		t.Fatalf("unreachable adapter: %v\n%s", err, out)
	}
}

// TestVerbsRoundTrip exercises the 4 client verbs against an httptest hub.
func TestVerbsRoundTrip(t *testing.T) {
	dir := onboardDir(t)
	db := filepath.Join(dir, "hub.db")
	if _, err := invokeOnboard(t, "--db", db, "connect", "--peer", "A", "--platform", "poll", "--allow", "B"); err != nil {
		t.Fatal(err)
	}
	if _, err := invokeOnboard(t, "--db", db, "connect", "--peer", "B", "--platform", "poll", "--allow", "A"); err != nil {
		t.Fatal(err)
	}
	s, err := store.New(db)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	h := api.New(s)
	wakeSvc, err := wake.NewService(wake.Config{Peers: map[string]wake.PeerConfig{"B": {Adapter: "none"}}})
	if err != nil {
		t.Fatal(err)
	}
	h.Wake = wakeSvc
	hub := httptest.NewServer(h)
	defer hub.Close()

	node := func(peer string, args ...string) string {
		t.Helper()
		out, err := invokeOnboard(t, append([]string{"--url", hub.URL,
			"--token-file", filepath.Join(dir, peer+".token"),
			"--outbox", filepath.Join(dir, "outbox-"+peer+".db")}, args...)...)
		if err != nil {
			t.Fatal(args, err)
		}
		return out
	}

	var m store.Message
	if err := json.Unmarshal([]byte(node("A", "send", "--to", "B", "--body", "ping", "--client-id", "v1")), &m); err != nil {
		t.Fatal(err)
	}
	var inbox struct {
		Messages []store.Message `json:"messages"`
	}
	if err := json.Unmarshal([]byte(node("B", "inbox")), &inbox); err != nil {
		t.Fatal(err)
	}
	if len(inbox.Messages) != 1 || inbox.Messages[0].Body != "ping" {
		t.Fatalf("inbox: %+v", inbox.Messages)
	}
	node("B", "ack", "--id", m.ID, "--receipt="+inbox.Messages[0].Receipt)
	if err := json.Unmarshal([]byte(node("B", "reply", "--parent", m.ID, "--body", "pong", "--client-id", "r1")), &m); err != nil {
		t.Fatal(err)
	}
	var st wake.Status
	if err := json.Unmarshal([]byte(node("B", "status")), &st); err != nil {
		t.Fatal(err)
	}
	if st.Peer != "B" || st.Adapter != "none" {
		t.Fatalf("status: %+v", st)
	}
	if err := json.Unmarshal([]byte(node("A", "inbox")), &inbox); err != nil {
		t.Fatal(err)
	}
	if len(inbox.Messages) != 1 || inbox.Messages[0].Body != "pong" {
		t.Fatalf("reply round-trip: %+v", inbox.Messages)
	}
}

// TestDoctorWakeStatusLive shows the last wake decision when a hub is live.
func TestDoctorWakeStatusLive(t *testing.T) {
	dir := onboardDir(t)
	db := filepath.Join(dir, "hub.db")
	if _, err := invokeOnboard(t, "--db", db, "connect", "--peer", "B", "--platform", "poll", "--allow", "admin"); err != nil {
		t.Fatal(err)
	}
	s, err := store.New(db)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	wakeSvc, err := wake.NewService(wake.Config{Peers: map[string]wake.PeerConfig{"B": {Adapter: "none"}}})
	if err != nil {
		t.Fatal(err)
	}
	h := api.New(s)
	h.Wake = wakeSvc
	hub := httptest.NewServer(h)
	defer hub.Close()
	if d := wakeSvc.Wake(t.Context(), "B", wake.Notice{ID: "m1", From: "admin"}); !d.Effective || d.Outcome != "delivered" {
		t.Fatalf("wake decision: %+v", d)
	}
	out, err := invokeOnboard(t, "--db", db, "--url", hub.URL,
		"--token-file", filepath.Join(dir, "B.token"), "--timeout", "5s", "doctor", "--peer", "B")
	if err != nil {
		t.Fatalf("doctor against live hub: %v\n%s", err, out)
	}
	if !strings.Contains(out, "OK wake") || !strings.Contains(out, "outcome=delivered") {
		t.Fatalf("wake status line missing:\n%s", out)
	}
	// Without a live hub the wake check is a SKIP, not a failure.
	hub.Close()
	out, err = invokeOnboard(t, "--db", db, "--url", "http://127.0.0.1:1",
		"--token-file", filepath.Join(dir, "B.token"), "doctor", "--peer", "B")
	if err != nil || !strings.Contains(out, "SKIP wake") {
		t.Fatalf("offline wake check must skip: %v\n%s", err, out)
	}
}

// TestDoctorLockedDBFallsBackToHubAPI runs doctor while a live hub holds the
// database lock: token/acl fall back to the hub API, and RELAYNOTE_URL feeds
// the global --url default.
func TestDoctorLockedDBFallsBackToHubAPI(t *testing.T) {
	dir := onboardDir(t)
	db := filepath.Join(dir, "hub.db")
	if _, err := invokeOnboard(t, "--db", db, "connect", "--peer", "B", "--platform", "poll", "--allow", "admin"); err != nil {
		t.Fatal(err)
	}
	// A running hub holds the exclusive bbolt lock; simulate with a live hub
	// over the same database.
	s, err := store.New(db)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	wakeSvc, err := wake.NewService(wake.Config{Peers: map[string]wake.PeerConfig{"B": {Adapter: "poll"}}})
	if err != nil {
		t.Fatal(err)
	}
	h := api.New(s)
	h.Wake = wakeSvc
	hub := httptest.NewServer(h)
	defer hub.Close()

	out, err := invokeOnboard(t, "--db", db, "--url", hub.URL,
		"--token-file", filepath.Join(dir, "B.token"), "--timeout", "5s", "doctor", "--peer", "B")
	if err != nil {
		t.Fatalf("doctor must succeed while the hub holds the database lock: %v\n%s", err, out)
	}
	for _, want := range []string{"OK token", "hub API", "SKIP acl", "OK adapter: adapter poll", "OK wake"} {
		if !strings.Contains(out, want) {
			t.Fatalf("doctor output missing %q:\n%s", want, out)
		}
	}

	// RELAYNOTE_URL is the global --url default; no --url flag needed.
	t.Setenv("RELAYNOTE_URL", hub.URL)
	out, err = invokeOnboard(t, "--token-file", filepath.Join(dir, "B.token"), "status")
	if err != nil {
		t.Fatalf("status via RELAYNOTE_URL: %v", err)
	}
	var st wake.Status
	if err := json.Unmarshal([]byte(out), &st); err != nil || st.Peer != "B" || st.Adapter != "poll" {
		t.Fatalf("status via RELAYNOTE_URL: %v\n%s", err, out)
	}
}
