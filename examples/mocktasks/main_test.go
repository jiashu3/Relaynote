package main

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"relaynote/internal/client"
	"relaynote/internal/store"
)

func testNetwork(t *testing.T, now func() time.Time) *mockNetwork {
	t.Helper()
	n, err := newMockNetwork(now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(n.close)
	return n
}

func request(id string) Envelope {
	return Envelope{Kind: "task.request", TaskID: id, Operation: "echo", Text: "literal synthetic text", TTL: deliveryTTL}
}

func sendRequest(t *testing.T, sender *mockNode, recipient, id string, e Envelope) store.Message {
	t.Helper()
	m, err := sender.send(context.Background(), recipient, id, e)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestAllTwelveDirections(t *testing.T) {
	n := testNetwork(t, nil)
	ctx := context.Background()
	parents := map[string]store.Message{}
	for _, from := range n.nodes {
		for _, to := range n.nodes {
			if from == to {
				continue
			}
			id := from.name + ":" + to.name
			m := sendRequest(t, from, to.name, id, request(id))
			parents[m.ID] = m
		}
	}
	received, err := n.drain(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(received) != 36 {
		t.Fatalf("got %d records, want 36", len(received))
	}
	seenRequests := map[string]bool{}
	seenStatuses := map[string]map[string]int{}
	for _, m := range received {
		e, err := decode(m.Body)
		if err != nil {
			t.Fatal(err)
		}
		if m.ExpiresAt-m.CreatedAt != deliveryTTL || e.TTL != deliveryTTL {
			t.Fatal("TTL is not 60 seconds")
		}
		if m.AgentAwakened != "unverified" {
			t.Fatalf("unexpected Agent awakening: %s", m.AgentAwakened)
		}
		if e.Kind == "task.request" {
			if _, ok := parents[m.ID]; !ok {
				t.Fatal("unplanned task request")
			}
			if seenRequests[m.ID] {
				t.Fatal("request delivered more than once")
			}
			seenRequests[m.ID] = true
			continue
		}
		if m.ReplyTo == nil {
			t.Fatal("status has no parent correlation")
		}
		parent, ok := parents[*m.ReplyTo]
		if !ok {
			t.Fatal("status does not reply to original task")
		}
		eq, err := decode(parent.Body)
		if err != nil {
			t.Fatal(err)
		}
		if e.TaskID != eq.TaskID || m.ThreadID != parent.ThreadID || m.Sender != parent.Recipient || m.Recipient != parent.Sender {
			t.Fatal("status correlation mismatch")
		}
		if e.Hop != maxHop || e.Operation != "echo" || e.Error != "" {
			t.Fatalf("invalid status: %+v", e)
		}
		if seenStatuses[parent.ID] == nil {
			seenStatuses[parent.ID] = map[string]int{}
		}
		seenStatuses[parent.ID][e.Kind]++
		switch e.Kind {
		case "task.running":
			if e.Result != "" {
				t.Fatal("running status contains a result")
			}
		case "task.completed":
			if e.Result != eq.Text {
				t.Fatal("echo result changed")
			}
		default:
			t.Fatalf("unexpected status %q", e.Kind)
		}
	}
	if len(seenRequests) != 12 {
		t.Fatalf("got %d directions, want 12", len(seenRequests))
	}
	for id := range parents {
		if seenStatuses[id]["task.running"] != 1 || seenStatuses[id]["task.completed"] != 1 {
			t.Fatal("missing or repeated status")
		}
	}
	for _, node := range n.nodes {
		for _, m := range received {
			if m.Recipient != node.name {
				continue
			}
			var saved store.Message
			if err := node.client.Do(ctx, http.MethodGet, "/v1/messages/"+m.ID, nil, &saved); err != nil {
				t.Fatal(err)
			}
			if saved.State != "acknowledged" {
				t.Fatalf("message %s not acknowledged", m.ID)
			}
		}
	}
	more, err := n.drain(ctx)
	if err != nil || len(more) != 0 {
		t.Fatalf("status ping-pong: %d records, %v", len(more), err)
	}
}

func TestSummary(t *testing.T) {
	got, err := runDemo(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := Summary{Nodes: 4, Directions: 12, Requests: 12, Running: 12, Completed: 12, Failed: 0,
		Acknowledged: 36, DeliveryTTL: 60, MaxHop: 1, AgentExecution: "mock-only"}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestRejectedRequestsHaveOneBoundedFailure(t *testing.T) {
	cases := []struct {
		name   string
		change func(*Envelope)
		reason string
	}{
		{"unsupported operation", func(e *Envelope) { e.Operation = "shell" }, "unsupported_operation"},
		{"exhausted hop", func(e *Envelope) { e.Hop = 1 }, "hop_exhausted"},
		{"excess hop", func(e *Envelope) { e.Hop = 1000 }, "hop_exhausted"},
		{"negative hop", func(e *Envelope) { e.Hop = -1 }, "hop_exhausted"},
		{"wrong ttl", func(e *Envelope) { e.TTL = 61 }, "invalid_ttl"},
		{"oversized text", func(e *Envelope) { e.Text = strings.Repeat("x", 257) }, "invalid_text"},
		{"empty text", func(e *Envelope) { e.Text = "" }, "invalid_text"},
		{"control characters", func(e *Envelope) { e.Text = "line\nbreak" }, "invalid_text"},
		{"result in request", func(e *Envelope) { e.Result = "unexpected" }, "invalid_request"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n := testNetwork(t, nil)
			e := request("reject")
			tc.change(&e)
			parent := sendRequest(t, n.nodes[0], n.nodes[1].name, "reject", e)
			received, err := n.drain(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if len(received) != 2 {
				t.Fatalf("got %d messages, want one request and one failure", len(received))
			}
			failure, err := decode(received[1].Body)
			if err != nil {
				t.Fatal(err)
			}
			if failure.Kind != "task.failed" || failure.Error != tc.reason || failure.Hop != 1 || failure.Result != "" || failure.Text != "" {
				t.Fatalf("invalid bounded failure: %+v", failure)
			}
			if received[1].ReplyTo == nil || *received[1].ReplyTo != parent.ID || failure.TaskID != e.TaskID {
				t.Fatal("failure missing correlation")
			}
			more, err := n.drain(context.Background())
			if err != nil || len(more) != 0 {
				t.Fatalf("failed status spawned messages: %v", err)
			}
		})
	}
}

func TestEveryStatusAndUnknownKindNeverTriggersTask(t *testing.T) {
	for _, kind := range []string{"task.running", "task.completed", "task.failed", "unknown"} {
		t.Run(kind, func(t *testing.T) {
			n := testNetwork(t, nil)
			e := request("status")
			e.Kind = kind // Otherwise valid task fields deliberately exercise the guard.
			sendRequest(t, n.nodes[0], n.nodes[1].name, "status", e)
			received, err := n.drain(context.Background())
			if err != nil || len(received) != 1 {
				t.Fatalf("status generated a reply: %d, %v", len(received), err)
			}
		})
	}
}

func TestLeaseRedeliveryDeduplicatesStatuses(t *testing.T) {
	var ticks atomic.Int64
	ticks.Store(time.Now().UnixNano())
	n := testNetwork(t, func() time.Time { return time.Unix(0, ticks.Load()) })
	ctx := context.Background()
	from, to := n.nodes[0], n.nodes[1]
	e := request("repeat")
	original := sendRequest(t, from, to.name, "repeat", e)
	repeated := sendRequest(t, from, to.name, "repeat", e)
	if original.ID != repeated.ID {
		t.Fatal("request retry was not deduplicated")
	}
	claimed, err := to.claim(ctx)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim: %+v, %v", claimed, err)
	}
	first, err := to.respond(ctx, claimed[0])
	if err != nil || len(first) != 2 {
		t.Fatalf("first processing: %+v, %v", first, err)
	}
	// Simulate a crash after the replies committed but before acknowledging.
	ticks.Add(int64(6 * time.Second))
	redelivered, err := to.claim(ctx)
	if err != nil || len(redelivered) != 1 {
		t.Fatalf("redelivery: %+v, %v", redelivered, err)
	}
	if redelivered[0].ID != original.ID || redelivered[0].Attempts != 2 || redelivered[0].Receipt == claimed[0].Receipt {
		t.Fatal("request did not undergo lease redelivery")
	}
	second, err := to.respond(ctx, redelivered[0])
	if err != nil || len(second) != 2 {
		t.Fatalf("reprocessing: %+v, %v", second, err)
	}
	for i := range first {
		if first[i].ID != second[i].ID || first[i].ClientID != second[i].ClientID {
			t.Fatal("redelivery duplicated a status")
		}
		status, err := decode(first[i].Body)
		if err != nil {
			t.Fatal(err)
		}
		if first[i].ClientID != "mock:"+original.ID+":"+status.Kind {
			t.Fatal("unstable status idempotency key")
		}
	}
	if err := to.ack(ctx, redelivered[0]); err != nil {
		t.Fatal(err)
	}
	statuses, err := n.drain(ctx)
	if err != nil || len(statuses) != 2 {
		t.Fatalf("got duplicate status records: %d, %v", len(statuses), err)
	}
}

func TestExplicitDestinationACLRejectsSelf(t *testing.T) {
	n := testNetwork(t, nil)
	for _, node := range n.nodes {
		_, err := node.send(context.Background(), node.name, "self", request("self"))
		var httpErr *client.HTTPError
		if !errors.As(err, &httpErr) || httpErr.Status != http.StatusForbidden {
			t.Fatalf("self-send did not return 403: %v", err)
		}
	}
}

func TestCommandLookingTextOnlyEchoed(t *testing.T) {
	n := testNetwork(t, nil)
	e := request("literal")
	e.Text = "$(printf unsafe); echo no-shell"
	sendRequest(t, n.nodes[0], n.nodes[1].name, "literal", e)
	received, err := n.drain(context.Background())
	if err != nil || len(received) != 3 {
		t.Fatalf("literal echo: %d, %v", len(received), err)
	}
	last, err := decode(received[2].Body)
	if err != nil || last.Kind != "task.completed" || last.Result != e.Text {
		t.Fatalf("text was not preserved literally: %+v, %v", last, err)
	}
}

func TestMalformedOrUncorrelatableInputNeverTriggersTask(t *testing.T) {
	for _, body := range []string{
		`not JSON`,
		`null`,
		`{"kind":"task.request","task_id":"","operation":"echo","text":"hi","hop":0,"ttl":60}`,
		`{"kind":"task.request","task_id":"bad id","operation":"echo","text":"hi","hop":0,"ttl":60}`,
		`{"kind":"task.request","task_id":"valid","operation":"echo","text":"hi","hop":0,"ttl":60,"extra":"unknown"}`,
		encode(request("trailing")) + ` {}`,
		strings.Repeat("x", maxEnvelopeBytes+1),
	} {
		n := testNetwork(t, nil)
		var out store.Message
		err := n.nodes[0].client.Do(context.Background(), http.MethodPost, "/v1/messages", store.SendRequest{
			To: n.nodes[1].name, Body: body, ClientID: "malformed", TTL: deliveryTTL,
		}, &out)
		if err != nil {
			t.Fatal(err)
		}
		received, err := n.drain(context.Background())
		if err != nil || len(received) != 1 {
			t.Fatalf("invalid input generated replies: %d, %v", len(received), err)
		}
	}
}

func TestRequestInsideReplyCannotStartTask(t *testing.T) {
	n := testNetwork(t, nil)
	ctx := context.Background()
	// Seed a status, then send a request as a reply to it. Only an explicit root
	// task request is eligible for the echo operation.
	status := request("nested")
	status.Kind = "task.completed"
	parent := sendRequest(t, n.nodes[0], n.nodes[1].name, "seed", status)
	nested, err := n.nodes[1].reply(ctx, parent, request("nested"))
	if err != nil {
		t.Fatal(err)
	}
	received, err := n.drain(ctx)
	if err != nil || len(received) != 3 {
		t.Fatalf("nested request lifecycle: %d, %v", len(received), err)
	}
	failures := 0
	for _, m := range received {
		e, err := decode(m.Body)
		if err != nil {
			t.Fatal(err)
		}
		if e.Kind == "task.failed" {
			failures++
			if e.Error != "invalid_request" || m.ReplyTo == nil || *m.ReplyTo != nested.ID {
				t.Fatal("invalid nested failure")
			}
		}
		if e.Kind == "task.running" {
			t.Fatal("nested request started an operation")
		}
	}
	if failures != 1 {
		t.Fatalf("got %d failures", failures)
	}
}
