// Package wake delivers optional wake-up notices to peers when messages
// arrive for them, behind per-peer gates (rate caps, quiet hours, circuit
// breaker, pause, hop limit). Everything is default-off: the hub only loads
// this package when serve --wake-config is provided. Notices carry only
// message metadata, never the body, unless a peer opts in to previews.
package wake

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"time"
)

// MaxPreview bounds the optional notice preview, in characters.
const MaxPreview = 200

// Notice is the wake-up payload for one inbound message.
type Notice struct {
	ID      string `json:"id"`
	Kind    string `json:"kind,omitempty"`
	From    string `json:"from"`
	Conv    string `json:"conv,omitempty"`
	Hop     int    `json:"hop,omitempty"`
	Preview string `json:"preview,omitempty"`
}

// Adapter delivers one notice to a peer.
type Adapter interface {
	Wake(ctx context.Context, n Notice) error
}

// None only enqueues; the peer collects messages by polling.
type None struct{}

func (None) Wake(context.Context, Notice) error { return nil }

// SinkFunc is the P2 hook for MCP event delivery: attach a function that
// forwards the notice to an MCP event subscription.
type SinkFunc func(ctx context.Context, n Notice) error

// EventSink adapts a pluggable sink to Adapter. With no sink attached it
// fails, so the gate's retry and breaker logic still apply.
type EventSink struct{ Sink SinkFunc }

func (e EventSink) Wake(ctx context.Context, n Notice) error {
	if e.Sink == nil {
		return errors.New("wake: no event sink attached")
	}
	return e.Sink(ctx, n)
}

func truncate(s string) string {
	r := []rune(s)
	if len(r) <= MaxPreview {
		return s
	}
	return string(r[:MaxPreview])
}

// Webhook posts the notice as JSON. The message body is never included
// unless the peer opts in to previews, and then at most MaxPreview
// characters. With a Secret, the body is signed with HMAC-SHA256.
type Webhook struct {
	URL     string
	Secret  string
	Preview bool
	Client  *http.Client
}

func (w *Webhook) Wake(ctx context.Context, n Notice) error {
	payload := struct {
		ID      string `json:"id"`
		Kind    string `json:"kind,omitempty"`
		From    string `json:"from"`
		Conv    string `json:"conv,omitempty"`
		Preview string `json:"preview,omitempty"`
	}{ID: n.ID, Kind: n.Kind, From: n.From, Conv: n.Conv}
	if w.Preview && n.Preview != "" {
		payload.Preview = truncate(n.Preview)
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if w.Secret != "" {
		mac := hmac.New(sha256.New, []byte(w.Secret))
		mac.Write(body)
		req.Header.Set("X-Relaynote-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	client := w.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("wake: webhook returned status %d", resp.StatusCode)
	}
	return nil
}

// Exec runs a local command with the path to a JSON notice file appended to
// its argv. No shell is involved; the notice file is removed afterwards.
type Exec struct{ Argv []string }

func (e *Exec) Wake(ctx context.Context, n Notice) error {
	if len(e.Argv) == 0 {
		return errors.New("wake: exec argv is empty")
	}
	f, err := os.CreateTemp("", "relaynote-wake-*.json")
	if err != nil {
		return err
	}
	path := f.Name()
	defer os.Remove(path)
	if err = json.NewEncoder(f).Encode(n); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	argv := append(append([]string{}, e.Argv...), path)
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("wake: exec %q failed: %w: %s", argv[0], err, truncate(string(out)))
	}
	return nil
}
