package events

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"relaynote/internal/store"
	"strings"
	"sync"
	"testing"
	"time"
)

func testSecret(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return "whsec_" + base64.StdEncoding.EncodeToString(b)
}

// receiver is a fake callback endpoint recording signed deliveries.
type receiver struct {
	mu       sync.Mutex
	srv      *httptest.Server
	status   int
	requests []recordedRequest
}

type recordedRequest struct {
	Body    string
	Headers http.Header
}

func newReceiver(t *testing.T, status int) *receiver {
	r := &receiver{status: status}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		buf, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		r.requests = append(r.requests, recordedRequest{Body: string(buf), Headers: req.Header.Clone()})
		r.mu.Unlock()
		var payload struct {
			Type      string `json:"type"`
			Challenge string `json:"challenge"`
		}
		if json.Unmarshal(buf, &payload) == nil && payload.Type == "verification" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(r.status)
			_ = json.NewEncoder(w).Encode(map[string]string{"challenge": payload.Challenge})
			return
		}
		w.WriteHeader(r.status)
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *receiver) calls() []recordedRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]recordedRequest{}, r.requests...)
}

func newService(t *testing.T) (*Service, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	st, err := store.New(filepath.Join(dir, "hub.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return New(st.DB(), &SafeHTTP{AllowInsecure: true}), st
}

func subParams(rawurl, secret string) map[string]any {
	return map[string]any{"name": EventName, "delivery": map[string]any{"mode": "webhook", "url": rawurl, "secret": secret}}
}

func TestSubscribeVerifyPublishDeliver(t *testing.T) {
	svc, _ := newService(t)
	now := 1791900000.0
	svc.Now = func() time.Time { return time.Unix(int64(now), 0) }
	r := newReceiver(t, 200)
	secret := testSecret(t)

	res, err := svc.Subscribe("dot", subParams(r.srv.URL+"/cb", secret))
	if err != nil {
		t.Fatal(err)
	}
	id, _ := res["id"].(string)
	if id == "" || res["refreshBefore"] == "" {
		t.Fatalf("bad subscribe result: %v", res)
	}
	// verification happened and echoed the challenge
	if len(r.calls()) != 1 {
		t.Fatalf("verification calls: %d", len(r.calls()))
	}
	if !VerifySignature(secret, r.calls()[0].Headers, []byte(r.calls()[0].Body), 300, svc.Now()) {
		t.Fatal("verification request not signed")
	}
	// deterministic: same params -> same id, cached verification (no 2nd call)
	res2, err := svc.Subscribe("dot", subParams(r.srv.URL+"/cb", secret))
	if err != nil {
		t.Fatal(err)
	}
	if res2["id"] != id || len(r.calls()) != 1 {
		t.Fatalf("idempotent subscribe: %v vs %v, calls %d", res2["id"], id, len(r.calls()))
	}

	// publish + deliver
	queued, err := svc.Publish(PublishData{
		"message_id": "m-1", "conversation_id": "c-1", "from": "grok-bot", "kind": "chat",
		"hop": 0, "reply_allowed": true, "preview": "hi", "created_at": utcISO(now),
	}, "evt_m-1", now)
	if err != nil || queued != 1 {
		t.Fatalf("publish: %d %v", queued, err)
	}
	stats, err := svc.DeliverDue(context.Background())
	if err != nil || stats.Delivered != 1 {
		t.Fatalf("deliver: %v %v", stats, err)
	}
	calls := r.calls()
	if len(calls) != 2 {
		t.Fatalf("deliveries: %d", len(calls))
	}
	if !VerifySignature(secret, calls[1].Headers, []byte(calls[1].Body), 300, svc.Now()) {
		t.Fatal("event delivery not signed")
	}
	var evt map[string]any
	if err := json.Unmarshal([]byte(calls[1].Body), &evt); err != nil {
		t.Fatal(err)
	}
	if evt["eventId"] != "evt_m-1" || evt["name"] != EventName {
		t.Fatalf("bad event body: %s", calls[1].Body)
	}
	if got := evt["data"].(map[string]any)["message_id"]; got != "m-1" {
		t.Fatalf("bad event data: %v", evt["data"])
	}
}

func TestSubscribeValidation(t *testing.T) {
	svc, _ := newService(t)
	r := newReceiver(t, 200)
	if _, err := svc.Subscribe("dot", map[string]any{"name": "nope"}); err == nil {
		t.Fatal("unknown event name accepted")
	}
	if _, err := svc.Subscribe("dot", map[string]any{"name": EventName,
		"delivery": map[string]any{"mode": "webhook", "url": r.srv.URL, "secret": "bad"}}); err == nil {
		t.Fatal("bad secret accepted")
	}
	// https required when not insecure
	strict := &SafeHTTP{HostAllow: []string{"example.com"}}
	if _, err := strict.CheckURL("http://example.com/cb"); err == nil || err.(*CallbackError).Reason != "insecure_url" {
		t.Fatalf("http accepted: %v", err)
	}
	if _, err := strict.CheckURL("https://evil.com/cb"); err == nil || err.(*CallbackError).Reason != "host_not_allowed" {
		t.Fatalf("evil host accepted: %v", err)
	}
	if _, err := strict.CheckURL("https://example.com:8443/cb"); err == nil || err.(*CallbackError).Reason != "port_not_allowed" {
		t.Fatalf("odd port accepted: %v", err)
	}
	if !HostAllowed("api.example.com", []string{"*.example.com"}) || HostAllowed("example.com", []string{"*.example.com"}) {
		t.Fatal("host matching broken")
	}
}

func TestChallengeFailure(t *testing.T) {
	svc, _ := newService(t)
	r := newReceiver(t, 500)
	_, err := svc.Subscribe("dot", subParams(r.srv.URL+"/cb", testSecret(t)))
	ce, ok := err.(*CallbackError)
	if !ok || ce.Reason != "challenge_failed" {
		t.Fatalf("want challenge_failed, got %v", err)
	}
}

func TestRetryBackoffAnd410(t *testing.T) {
	svc, _ := newService(t)
	now := 1791900000.0
	svc.Now = func() time.Time { return time.Unix(int64(now), 0) }
	r := newReceiver(t, 500)
	secret := testSecret(t)
	// verification also fails with 500 -> subscribe refuses; use a good receiver
	// for subscribe, then swap the subscription URL is not possible, so instead
	// subscribe against a 200 receiver and flip it to failing.
	r.status = 200
	if _, err := svc.Subscribe("dot", subParams(r.srv.URL+"/cb", secret)); err != nil {
		t.Fatal(err)
	}
	r.status = 500
	if _, err := svc.Publish(PublishData{"message_id": "m-1"}, "evt_m-1", now); err != nil {
		t.Fatal(err)
	}
	stats, _ := svc.DeliverDue(context.Background())
	if stats.Retrying != 1 || stats.Delivered != 0 {
		t.Fatalf("want retrying, got %v", stats)
	}
	// not due yet
	stats, _ = svc.DeliverDue(context.Background())
	if stats != (DeliverStats{}) {
		t.Fatalf("premature retry: %v", stats)
	}
	now += RetryDelays[0] + 1
	stats, _ = svc.DeliverDue(context.Background())
	if stats.Retrying != 1 {
		t.Fatalf("second attempt: %v", stats)
	}
	// 410 deletes the subscription and fails the entry
	r.status = 410
	now += RetryDelays[1] + 1
	stats, _ = svc.DeliverDue(context.Background())
	if stats.Failed != 1 {
		t.Fatalf("410: %v", stats)
	}
	if svc.ActiveCount() != 0 {
		t.Fatal("410 did not delete the subscription")
	}
}

func TestUnsubscribeCancelsPending(t *testing.T) {
	svc, _ := newService(t)
	r := newReceiver(t, 200)
	secret := testSecret(t)
	rawurl := r.srv.URL + "/cb"
	if _, err := svc.Subscribe("dot", subParams(rawurl, secret)); err != nil {
		t.Fatal(err)
	}
	r.status = 500
	if _, err := svc.Publish(PublishData{"message_id": "m-1"}, "evt_m-1", svc.now()); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Unsubscribe("dot", subParams(rawurl, secret)); err != nil {
		t.Fatal(err)
	}
	stats, _ := svc.DeliverDue(context.Background())
	if stats != (DeliverStats{}) {
		t.Fatalf("unsubscribe left pending entries: %v", stats)
	}
	if svc.ActiveCount() != 0 {
		t.Fatal("subscription still active")
	}
}

func TestSecretRotationDualSignature(t *testing.T) {
	svc, _ := newService(t)
	r := newReceiver(t, 200)
	secret1, secret2 := testSecret(t), testSecret(t)
	rawurl := r.srv.URL + "/cb"
	res, err := svc.Subscribe("dot", subParams(rawurl, secret1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Subscribe("dot", subParams(rawurl, secret2)); err != nil {
		t.Fatal(err)
	}
	_ = res
	if _, err := svc.Publish(PublishData{"message_id": "m-9"}, "evt_m-9", svc.now()); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.DeliverDue(context.Background()); err != nil {
		t.Fatal(err)
	}
	calls := r.calls()
	last := calls[len(calls)-1]
	sigs := last.Headers.Get("webhook-signature")
	if len(strings.Fields(sigs)) != 2 {
		t.Fatalf("want dual signature during rotation, got %q", sigs)
	}
	if !VerifySignature(secret2, last.Headers, []byte(last.Body), 300, time.Now()) {
		t.Fatal("new secret signature invalid")
	}
	if !VerifySignature(secret1, last.Headers, []byte(last.Body), 300, time.Now()) {
		t.Fatal("old secret signature invalid during rotation window")
	}
}
