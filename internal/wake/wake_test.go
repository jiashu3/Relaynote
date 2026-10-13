package wake

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock(t time.Time) *fakeClock { return &fakeClock{t: t} }
func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}
func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type fakeAdapter struct {
	mu      sync.Mutex
	errs    []error
	calls   int
	notices []Notice
}

func (f *fakeAdapter) Wake(_ context.Context, n Notice) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.notices = append(f.notices, n)
	if len(f.errs) > 0 {
		err := f.errs[0]
		f.errs = f.errs[1:]
		return err
	}
	return nil
}

// testService builds a Service over one peer with a fake clock; when ad is
// non-nil it replaces the configured adapter.
func testService(t *testing.T, start time.Time, peer string, cfg PeerConfig, ad Adapter) (*Service, *fakeClock) {
	t.Helper()
	svc, err := NewService(Config{Peers: map[string]PeerConfig{peer: cfg}})
	if err != nil {
		t.Fatal(err)
	}
	if ad != nil {
		svc.adapters[peer] = ad
	}
	clock := newFakeClock(start)
	svc.Now = clock.now
	svc.Sleep = func(_ context.Context, d time.Duration) error {
		clock.advance(d)
		return nil
	}
	return svc, clock
}

var noon = time.Date(2026, 10, 13, 12, 0, 0, 0, time.Local)

func notice(id string) Notice { return Notice{ID: id, From: "A", Kind: "note"} }

func TestWebhookOmitsBodyByDefault(t *testing.T) {
	var bodies [][]byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		bodies = append(bodies, data)
	}))
	defer server.Close()
	svc, _ := testService(t, noon, "B", PeerConfig{Adapter: "webhook", WebhookURL: server.URL}, nil)
	n := notice("m1")
	n.Conv = "c1"
	n.Preview = "the secret message body"
	d := svc.Wake(context.Background(), "B", n)
	if !d.Effective || d.Outcome != "delivered" {
		t.Fatalf("unexpected decision %+v", d)
	}
	var payload map[string]any
	if err := json.Unmarshal(bodies[0], &payload); err != nil {
		t.Fatal(err)
	}
	if _, ok := payload["preview"]; ok {
		t.Fatalf("preview must be off by default: %s", bodies[0])
	}
	if strings.Contains(string(bodies[0]), "secret") {
		t.Fatalf("webhook leaked message body: %s", bodies[0])
	}
	if payload["id"] != "m1" || payload["from"] != "A" || payload["kind"] != "note" || payload["conv"] != "c1" {
		t.Fatalf("missing metadata: %s", bodies[0])
	}
}

func TestWebhookPreviewOptInTruncates(t *testing.T) {
	var bodies [][]byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		bodies = append(bodies, data)
	}))
	defer server.Close()
	svc, _ := testService(t, noon, "B", PeerConfig{Adapter: "webhook", WebhookURL: server.URL, Preview: true}, nil)
	n := notice("m1")
	n.Preview = strings.Repeat("x", 300)
	if d := svc.Wake(context.Background(), "B", n); d.Outcome != "delivered" {
		t.Fatalf("unexpected decision %+v", d)
	}
	var payload map[string]any
	if err := json.Unmarshal(bodies[0], &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload["preview"].(string)) != MaxPreview {
		t.Fatalf("preview not truncated to %d: %s", MaxPreview, bodies[0])
	}
}

func TestWebhookHMACSignature(t *testing.T) {
	var body []byte
	var signature string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		signature = r.Header.Get("X-Relaynote-Signature")
	}))
	defer server.Close()
	svc, _ := testService(t, noon, "B", PeerConfig{Adapter: "webhook", WebhookURL: server.URL, HMACSecret: "k"}, nil)
	svc.Wake(context.Background(), "B", notice("m1"))
	mac := hmac.New(sha256.New, []byte("k"))
	mac.Write(body)
	if want := "sha256=" + hex.EncodeToString(mac.Sum(nil)); signature != want {
		t.Fatalf("signature %q, want %q", signature, want)
	}
}

func TestRateCapsWithFakeClock(t *testing.T) {
	ad := &fakeAdapter{}
	svc, clock := testService(t, noon, "B", PeerConfig{Adapter: "none", MinInterval: 60, PerHour: 2}, ad)
	if d := svc.Wake(context.Background(), "B", notice("m1")); !d.Effective {
		t.Fatalf("first wake suppressed: %+v", d)
	}
	if d := svc.Wake(context.Background(), "B", notice("m2")); d.Effective || d.Reason != "min_interval" {
		t.Fatalf("min_interval expected: %+v", d)
	}
	clock.advance(61 * time.Second)
	if d := svc.Wake(context.Background(), "B", notice("m3")); !d.Effective {
		t.Fatalf("wake after min_interval suppressed: %+v", d)
	}
	clock.advance(61 * time.Second)
	if d := svc.Wake(context.Background(), "B", notice("m4")); d.Effective || d.Reason != "per_hour_cap" {
		t.Fatalf("per_hour_cap expected: %+v", d)
	}
	clock.advance(time.Hour)
	if d := svc.Wake(context.Background(), "B", notice("m5")); !d.Effective {
		t.Fatalf("wake after window suppressed: %+v", d)
	}
}

func TestPerDayCap(t *testing.T) {
	svc, clock := testService(t, noon, "B", PeerConfig{Adapter: "none", PerDay: 1}, &fakeAdapter{})
	if d := svc.Wake(context.Background(), "B", notice("m1")); !d.Effective {
		t.Fatalf("first wake suppressed: %+v", d)
	}
	clock.advance(2 * time.Hour)
	if d := svc.Wake(context.Background(), "B", notice("m2")); d.Effective || d.Reason != "per_day_cap" {
		t.Fatalf("per_day_cap expected: %+v", d)
	}
	clock.advance(23 * time.Hour)
	if d := svc.Wake(context.Background(), "B", notice("m3")); !d.Effective {
		t.Fatalf("wake next day suppressed: %+v", d)
	}
}

func TestQuietHoursDeferNotDrop(t *testing.T) {
	ad := &fakeAdapter{}
	at2300 := time.Date(2026, 10, 13, 23, 0, 0, 0, time.Local)
	svc, clock := testService(t, at2300, "B", PeerConfig{Adapter: "none", QuietStart: "22:00", QuietEnd: "07:00"}, ad)
	d := svc.Wake(context.Background(), "B", notice("m1"))
	if d.Effective || d.Reason != "quiet_hours_deferred" {
		t.Fatalf("quiet_hours_deferred expected: %+v", d)
	}
	if ad.calls != 0 {
		t.Fatal("adapter called during quiet hours")
	}
	if st := svc.Status("B"); st.Deferred != 1 {
		t.Fatalf("deferred notice not queued: %+v", st)
	}
	clock.advance(9 * time.Hour) // 08:00 next day
	d = svc.Wake(context.Background(), "B", notice("m2"))
	if !d.Effective {
		t.Fatalf("wake after quiet hours suppressed: %+v", d)
	}
	if ad.calls != 2 || ad.notices[0].ID != "m1" || ad.notices[1].ID != "m2" {
		t.Fatalf("deferred notice not flushed before the new one: %+v", ad.notices)
	}
	if st := svc.Status("B"); st.Deferred != 0 {
		t.Fatalf("deferred queue not drained: %+v", st)
	}
}

func TestBreakerOpensAndRecovers(t *testing.T) {
	ad := &fakeAdapter{errs: []error{errors.New("down"), errors.New("down"), errors.New("down")}}
	svc, clock := testService(t, noon, "B",
		PeerConfig{Adapter: "none", BreakerFailures: 3, BreakerCooldown: 300}, ad)
	for i := 0; i < 3; i++ {
		if d := svc.Wake(context.Background(), "B", notice("m")); d.Outcome != "failed" {
			t.Fatalf("wake %d: %+v", i, d)
		}
	}
	if st := svc.Status("B"); st.Breaker != "open" || st.ConsecutiveFailures != 3 {
		t.Fatalf("breaker not open: %+v", st)
	}
	if d := svc.Wake(context.Background(), "B", notice("m4")); d.Effective || d.Reason != "breaker_open" {
		t.Fatalf("breaker_open expected: %+v", d)
	}
	if ad.calls != 3 {
		t.Fatal("adapter called while breaker open")
	}
	clock.advance(301 * time.Second)
	if st := svc.Status("B"); st.Breaker != "half_open" {
		t.Fatalf("breaker not half-open after cooldown: %+v", st)
	}
	if d := svc.Wake(context.Background(), "B", notice("m5")); d.Outcome != "delivered" {
		t.Fatalf("half-open trial failed: %+v", d)
	}
	if st := svc.Status("B"); st.Breaker != "closed" || st.ConsecutiveFailures != 0 {
		t.Fatalf("breaker not closed after success: %+v", st)
	}
}

func TestBreakerReopensOnFailedTrial(t *testing.T) {
	ad := &fakeAdapter{errs: []error{errors.New("x"), errors.New("x"), errors.New("x"), errors.New("x")}}
	svc, clock := testService(t, noon, "B",
		PeerConfig{Adapter: "none", BreakerFailures: 3, BreakerCooldown: 300}, ad)
	for i := 0; i < 3; i++ {
		svc.Wake(context.Background(), "B", notice("m"))
	}
	clock.advance(301 * time.Second)
	if d := svc.Wake(context.Background(), "B", notice("m4")); d.Outcome != "failed" {
		t.Fatalf("half-open trial should fail: %+v", d)
	}
	if st := svc.Status("B"); st.Breaker != "open" {
		t.Fatalf("breaker did not re-open: %+v", st)
	}
	if d := svc.Wake(context.Background(), "B", notice("m5")); d.Reason != "breaker_open" {
		t.Fatalf("breaker_open expected: %+v", d)
	}
	if ad.calls != 4 {
		t.Fatalf("adapter called while re-opened: %d", ad.calls)
	}
}

func TestRetryOnTransientWebhookFailure(t *testing.T) {
	hits := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if hits == 1 {
			w.WriteHeader(500)
		}
	}))
	defer server.Close()
	svc, _ := testService(t, noon, "B",
		PeerConfig{Adapter: "webhook", WebhookURL: server.URL, RetryMax: 2, RetryBackoff: 1}, nil)
	d := svc.Wake(context.Background(), "B", notice("m1"))
	if d.Outcome != "delivered" || d.Attempts != 2 || hits != 2 {
		t.Fatalf("transient failure not retried: %+v hits=%d", d, hits)
	}
}

func TestRetryExhaustedCountsFailure(t *testing.T) {
	hits := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(500)
	}))
	defer server.Close()
	svc, _ := testService(t, noon, "B",
		PeerConfig{Adapter: "webhook", WebhookURL: server.URL, RetryMax: 2, RetryBackoff: 1}, nil)
	d := svc.Wake(context.Background(), "B", notice("m1"))
	if d.Outcome != "failed" || d.Attempts != 3 || hits != 3 {
		t.Fatalf("bounded retry expected: %+v hits=%d", d, hits)
	}
	if st := svc.Status("B"); st.Failed != 1 || st.ConsecutiveFailures != 1 {
		t.Fatalf("failure not recorded: %+v", st)
	}
}

func TestPauseResume(t *testing.T) {
	ad := &fakeAdapter{}
	svc, _ := testService(t, noon, "B", PeerConfig{Adapter: "none"}, ad)
	svc.Pause("B")
	if d := svc.Wake(context.Background(), "B", notice("m1")); d.Effective || d.Reason != "paused" {
		t.Fatalf("paused expected: %+v", d)
	}
	svc.Resume("B")
	if d := svc.Wake(context.Background(), "B", notice("m2")); d.Outcome != "delivered" {
		t.Fatalf("resume failed: %+v", d)
	}
}

func TestHopLimit(t *testing.T) {
	ad := &fakeAdapter{}
	svc, _ := testService(t, noon, "B", PeerConfig{Adapter: "none", HopLimit: 2}, ad)
	n := notice("m1")
	n.Hop = 3
	if d := svc.Wake(context.Background(), "B", n); d.Effective || d.Reason != "hop_limit" {
		t.Fatalf("hop_limit expected: %+v", d)
	}
	n.Hop = 1
	if d := svc.Wake(context.Background(), "B", n); d.Outcome != "delivered" {
		t.Fatalf("hop within limit suppressed: %+v", d)
	}
}

func TestExecAdapter(t *testing.T) {
	if _, err := exec.LookPath("test"); err != nil {
		t.Skip("test binary unavailable")
	}
	svc, _ := testService(t, noon, "B", PeerConfig{Adapter: "exec", ExecArgv: []string{"test", "-f"}}, nil)
	if d := svc.Wake(context.Background(), "B", notice("m1")); d.Outcome != "delivered" {
		t.Fatalf("exec wake failed: %+v", d)
	}
	if _, err := exec.LookPath("false"); err != nil {
		t.Skip("false binary unavailable")
	}
	svc2, _ := testService(t, noon, "B", PeerConfig{Adapter: "exec", ExecArgv: []string{"false"}}, nil)
	if d := svc2.Wake(context.Background(), "B", notice("m1")); d.Outcome != "failed" {
		t.Fatalf("failing exec not reported: %+v", d)
	}
}

func TestEventSinkHook(t *testing.T) {
	svc, _ := testService(t, noon, "B", PeerConfig{Adapter: "mcp-event"}, nil)
	if d := svc.Wake(context.Background(), "B", notice("m1")); d.Outcome != "failed" {
		t.Fatalf("unattached sink should fail: %+v", d)
	}
	var got Notice
	if err := svc.SetSink("B", func(_ context.Context, n Notice) error { got = n; return nil }); err != nil {
		t.Fatal(err)
	}
	if d := svc.Wake(context.Background(), "B", notice("m2")); d.Outcome != "delivered" || got.ID != "m2" {
		t.Fatalf("sink not invoked: %+v %+v", d, got)
	}
	if err := svc.SetSink("C", nil); err == nil {
		t.Fatal("SetSink accepted a non-mcp-event peer")
	}
}

func TestUnknownPeerNeverWoken(t *testing.T) {
	svc, _ := testService(t, noon, "B", PeerConfig{Adapter: "none"}, nil)
	if d := svc.Wake(context.Background(), "C", notice("m1")); d.Effective || d.Reason != "no_adapter" {
		t.Fatalf("unconfigured peer woken: %+v", d)
	}
}

func TestLoadConfigValidation(t *testing.T) {
	dir := t.TempDir()
	bad := func(content string) {
		t.Helper()
		path := dir + "/c.json"
		if err := writeFile(path, content); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadConfig(path); err == nil {
			t.Fatalf("invalid config accepted: %s", content)
		}
	}
	bad(`{"peers":{"B":{"adapter":"carrier-pigeon"}}}`)
	bad(`{"peers":{"B":{"adapter":"webhook"}}}`)
	bad(`{"peers":{"B":{"adapter":"webhook","webhook_url":"ftp://x"}}}`)
	bad(`{"peers":{"B":{"adapter":"exec"}}}`)
	bad(`{"peers":{"B":{"quiet_start":"22:00"}}}`)
	bad(`{"peers":{"B":{"quiet_start":"25:00","quiet_end":"07:00"}}}`)
	bad(`{"peers":{"B":{"retry_max":9}}}`)
	bad(`{"peers":{"B":{"adapter":"none","bogus":1}}}`)
	path := dir + "/ok.json"
	if err := writeFile(path, `{"peers":{"B":{"adapter":"webhook","webhook_url":"http://127.0.0.1:9/w","quiet_start":"22:00","quiet_end":"07:00","per_hour":5}}}`); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err != nil {
		t.Fatal(err)
	}
}

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0600)
}
