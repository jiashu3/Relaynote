// Command mocktasks demonstrates an echo-only task lifecycle using a temporary
// loopback relay. It has no connection to a terminal, model, or real Agent.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"relaynote/internal/api"
	"relaynote/internal/client"
	"relaynote/internal/store"
)

const (
	deliveryTTL      = 60
	maxHop           = 1
	maxTextBytes     = 256
	maxEnvelopeBytes = 2048
)

var nodeNames = []string{"alpha", "bravo", "charlie", "delta"}
var taskIDPattern = regexp.MustCompile(`^[a-zA-Z0-9_.:-]{1,96}$`)

// Envelope is application data inside the relay's opaque body. A status is
// correlated by TaskID and the relay's ReplyTo/ThreadID, never by free text.
type Envelope struct {
	Kind      string `json:"kind"`
	TaskID    string `json:"task_id"`
	Operation string `json:"operation"`
	Text      string `json:"text,omitempty"`
	Result    string `json:"result,omitempty"`
	Error     string `json:"error,omitempty"`
	Hop       int    `json:"hop"`
	TTL       int    `json:"ttl"`
}

type mockNode struct {
	name   string
	client *client.Client
}

type mockNetwork struct {
	store  *store.Store
	server *httptest.Server
	nodes  []*mockNode
	dir    string
}

// No external URL, token, environment variable, or user configuration is read.
// Synthetic credentials are freshly generated and used only by this server.
func newMockNetwork(now func() time.Time) (_ *mockNetwork, err error) {
	n := &mockNetwork{}
	n.dir, err = os.MkdirTemp("", "relaynote-mocktasks-")
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			n.close()
		}
	}()
	n.store, err = store.New(filepath.Join(n.dir, "mock.db"))
	if err != nil {
		return nil, err
	}
	n.store.Now = now
	n.server = httptest.NewServer(api.New(n.store))
	for _, name := range nodeNames {
		allowed := make([]string, 0, len(nodeNames)-1)
		for _, other := range nodeNames {
			if other != name {
				allowed = append(allowed, other)
			}
		}
		token, e := store.NewToken()
		if e != nil {
			return nil, e
		}
		if e = n.store.Provision(name, allowed, token); e != nil {
			return nil, e
		}
		c, e := client.New(client.Config{BaseURL: n.server.URL, Token: token})
		if e != nil {
			return nil, e
		}
		n.nodes = append(n.nodes, &mockNode{name: name, client: c})
	}
	return n, nil
}

func (n *mockNetwork) close() {
	if n.server != nil {
		n.server.Close()
	}
	if n.store != nil {
		_ = n.store.Close()
	}
	if n.dir != "" {
		_ = os.RemoveAll(n.dir)
	}
}

func encode(e Envelope) string {
	data, _ := json.Marshal(e) // This struct has no unsupported JSON values.
	return string(data)
}

func decode(body string) (Envelope, error) {
	var e Envelope
	if len(body) > maxEnvelopeBytes || !utf8.ValidString(body) {
		return e, errors.New("invalid envelope")
	}
	d := json.NewDecoder(strings.NewReader(body))
	d.DisallowUnknownFields()
	if err := d.Decode(&e); err != nil {
		return Envelope{}, err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return Envelope{}, errors.New("trailing envelope data")
	}
	return e, nil
}

func (n *mockNode) send(ctx context.Context, to, id string, e Envelope) (store.Message, error) {
	var out store.Message
	err := n.client.Do(ctx, http.MethodPost, "/v1/messages", store.SendRequest{
		To: to, Body: encode(e), ClientID: id, TTL: deliveryTTL,
	}, &out)
	return out, err
}

func (n *mockNode) claim(ctx context.Context) ([]store.Message, error) {
	var out struct {
		Messages []store.Message `json:"messages"`
	}
	err := n.client.Do(ctx, http.MethodPost, "/v1/inbox/claim", map[string]int{"limit": 100, "lease": 5}, &out)
	return out.Messages, err
}

func (n *mockNode) ack(ctx context.Context, m store.Message) error {
	return n.client.Do(ctx, http.MethodPost, "/v1/messages/"+m.ID+"/ack", map[string]string{"receipt": m.Receipt}, nil)
}

// Stable IDs deduplicate only status records. Repeating a request can repeat the
// echo calculation; it must never be mistaken for exactly-once side effects.
func (n *mockNode) reply(ctx context.Context, parent store.Message, e Envelope) (store.Message, error) {
	var out store.Message
	err := n.client.Do(ctx, http.MethodPost, "/v1/messages/"+parent.ID+"/reply", map[string]any{
		"body": encode(e), "client_id": "mock:" + parent.ID + ":" + e.Kind, "ttl": deliveryTTL,
	}, &out)
	return out, err
}

func requestFailure(e Envelope, m store.Message) string {
	if e.Operation != "echo" {
		return "unsupported_operation"
	}
	if e.Hop < 0 || e.Hop >= maxHop {
		return "hop_exhausted"
	}
	if e.TTL != deliveryTTL {
		return "invalid_ttl"
	}
	if m.ReplyTo != nil || e.Result != "" || e.Error != "" {
		return "invalid_request"
	}
	if len(e.Text) == 0 || len(e.Text) > maxTextBytes || !utf8.ValidString(e.Text) {
		return "invalid_text"
	}
	for _, r := range e.Text {
		if unicode.IsControl(r) {
			return "invalid_text"
		}
	}
	return ""
}

// respond handles only explicit task.request envelopes. All status envelopes,
// unknown kinds, and malformed/uncorrelatable input generate zero replies.
// Even a string that resembles a command remains literal echo data.
func (n *mockNode) respond(ctx context.Context, m store.Message) ([]store.Message, error) {
	e, err := decode(m.Body)
	if err != nil || e.Kind != "task.request" || !taskIDPattern.MatchString(e.TaskID) {
		return nil, nil
	}
	status := Envelope{TaskID: e.TaskID, Operation: "echo", Hop: maxHop, TTL: deliveryTTL}
	if reason := requestFailure(e, m); reason != "" {
		status.Kind, status.Error = "task.failed", reason
		reply, err := n.reply(ctx, m, status)
		if err != nil {
			return nil, err
		}
		return []store.Message{reply}, nil
	}
	status.Kind = "task.running"
	running, err := n.reply(ctx, m, status)
	if err != nil {
		return nil, err
	}
	// The complete mock "operation" is this in-memory string assignment.
	status.Kind, status.Result = "task.completed", e.Text
	completed, err := n.reply(ctx, m, status)
	if err != nil {
		return nil, err
	}
	return []store.Message{running, completed}, nil
}

// drain uses a finite safety bound; statuses are acknowledged, never forwarded.
func (n *mockNetwork) drain(ctx context.Context) ([]store.Message, error) {
	var received []store.Message
	for pass := 0; pass < 8; pass++ {
		count := 0
		for _, node := range n.nodes {
			messages, err := node.claim(ctx)
			if err != nil {
				return nil, err
			}
			for _, m := range messages {
				if len(received) >= 96 {
					return nil, errors.New("mock message safety bound exceeded")
				}
				if _, err := node.respond(ctx, m); err != nil {
					return nil, err
				}
				if err := node.ack(ctx, m); err != nil {
					return nil, err
				}
				received = append(received, m)
				count++
			}
		}
		if count == 0 {
			return received, nil
		}
	}
	return nil, errors.New("mock drain safety bound exceeded")
}

type Summary struct {
	Nodes          int    `json:"nodes"`
	Directions     int    `json:"verified_directions"`
	Requests       int    `json:"requests"`
	Running        int    `json:"running"`
	Completed      int    `json:"completed"`
	Failed         int    `json:"failed"`
	Acknowledged   int    `json:"acknowledged"`
	DeliveryTTL    int    `json:"delivery_ttl_seconds"`
	MaxHop         int    `json:"max_hop"`
	AgentExecution string `json:"agent_execution"`
}

func runDemo(ctx context.Context) (Summary, error) {
	summary := Summary{Nodes: len(nodeNames), DeliveryTTL: deliveryTTL, MaxHop: maxHop, AgentExecution: "mock-only"}
	n, err := newMockNetwork(nil)
	if err != nil {
		return summary, err
	}
	defer n.close()
	requests := map[string]store.Message{}
	for _, sender := range n.nodes {
		for _, recipient := range n.nodes {
			if sender == recipient {
				continue
			}
			id := "task:" + sender.name + ":" + recipient.name
			m, err := sender.send(ctx, recipient.name, id, Envelope{
				Kind: "task.request", TaskID: id, Operation: "echo",
				Text: "hello from " + sender.name + " to " + recipient.name, Hop: 0, TTL: deliveryTTL,
			})
			if err != nil {
				return summary, err
			}
			requests[m.ID] = m
		}
	}
	received, err := n.drain(ctx)
	if err != nil {
		return summary, err
	}
	counts := map[string]map[string]int{}
	for _, m := range received {
		e, err := decode(m.Body)
		if err != nil {
			return summary, err
		}
		if m.AgentAwakened != "unverified" {
			return summary, errors.New("unexpected Agent execution claim")
		}
		if e.Kind == "task.request" {
			summary.Requests++
			continue
		}
		if m.ReplyTo == nil {
			return summary, errors.New("status missing parent")
		}
		parent, ok := requests[*m.ReplyTo]
		if !ok {
			return summary, errors.New("status has unknown parent")
		}
		request, _ := decode(parent.Body)
		if e.TaskID != request.TaskID || m.ThreadID != parent.ThreadID || m.Sender != parent.Recipient || m.Recipient != parent.Sender {
			return summary, errors.New("status correlation mismatch")
		}
		if counts[parent.ID] == nil {
			counts[parent.ID] = map[string]int{}
		}
		counts[parent.ID][e.Kind]++
		switch e.Kind {
		case "task.running":
			summary.Running++
		case "task.completed":
			if e.Result != request.Text {
				return summary, errors.New("echo mismatch")
			}
			summary.Completed++
		case "task.failed":
			summary.Failed++
		default:
			return summary, errors.New("unknown status")
		}
	}
	for id := range requests {
		if counts[id]["task.running"] != 1 || counts[id]["task.completed"] != 1 || counts[id]["task.failed"] != 0 {
			return summary, errors.New("incomplete or repeated lifecycle")
		}
		summary.Directions++
	}
	summary.Acknowledged = len(received)
	if summary.Requests != 12 || summary.Directions != 12 || summary.Acknowledged != 36 {
		return summary, errors.New("unexpected lifecycle totals")
	}
	return summary, nil
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	summary, err := runDemo(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "mock demo failed:", err)
		os.Exit(1)
	}
	if err := json.NewEncoder(os.Stdout).Encode(summary); err != nil {
		os.Exit(1)
	}
}
