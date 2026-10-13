package wake

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// PeerConfig gates and routes wake notices for one peer. Zero values mean:
// adapter "none" (enqueue only), no rate caps, no quiet hours, no breaker,
// two bounded retries, unlimited hops.
type PeerConfig struct {
	Adapter         string   `json:"adapter"` // none|poll|webhook|exec|mcp-event (poll behaves as none)
	WebhookURL      string   `json:"webhook_url,omitempty"`
	HMACSecret      string   `json:"hmac_secret,omitempty"`
	ExecArgv        []string `json:"exec_argv,omitempty"`
	Preview         bool     `json:"preview,omitempty"` // include <=200 chars of the body
	MinInterval     int      `json:"min_interval,omitempty"`
	PerHour         int      `json:"per_hour,omitempty"`
	PerDay          int      `json:"per_day,omitempty"`
	QuietStart      string   `json:"quiet_start,omitempty"` // "HH:MM" local
	QuietEnd        string   `json:"quiet_end,omitempty"`
	BreakerFailures int      `json:"breaker_failures,omitempty"` // consecutive failures to open; 0 disables
	BreakerCooldown int      `json:"breaker_cooldown,omitempty"` // seconds until a half-open trial
	RetryMax        int      `json:"retry_max,omitempty"`        // extra attempts after the first
	RetryBackoff    int      `json:"retry_backoff,omitempty"`    // base backoff seconds, doubling
	HopLimit        int      `json:"hop_limit,omitempty"`        // suppress notices above this hop count
	Paused          bool     `json:"paused,omitempty"`
}

// Config is the JSON document behind serve --wake-config.
type Config struct {
	Peers map[string]PeerConfig `json:"peers"`
}

// LoadConfig reads and validates a wake config file.
func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var cfg Config
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("wake config: %w", err)
	}
	for peer, p := range cfg.Peers {
		if err = validate(peer, p); err != nil {
			return Config{}, err
		}
	}
	return cfg, nil
}

func parseClock(value string) (int, error) {
	var h, m int
	if _, err := fmt.Sscanf(value, "%d:%d", &h, &m); err != nil || h < 0 || h > 23 || m < 0 || m > 59 || len(value) != 5 || value[2] != ':' {
		return 0, fmt.Errorf("invalid quiet hours time %q; want HH:MM", value)
	}
	return h*60 + m, nil
}

func validate(peer string, p PeerConfig) error {
	switch p.Adapter {
	case "", "none", "poll":
	case "webhook":
		u, err := url.Parse(p.WebhookURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("wake config %s: webhook_url must be an http(s) URL", peer)
		}
	case "exec":
		if len(p.ExecArgv) == 0 {
			return fmt.Errorf("wake config %s: exec_argv is required", peer)
		}
	case "mcp-event":
	default:
		return fmt.Errorf("wake config %s: unknown adapter %q", peer, p.Adapter)
	}
	if (p.QuietStart == "") != (p.QuietEnd == "") {
		return fmt.Errorf("wake config %s: quiet_start and quiet_end come in pairs", peer)
	}
	if p.QuietStart != "" {
		if _, err := parseClock(p.QuietStart); err != nil {
			return fmt.Errorf("wake config %s: %w", peer, err)
		}
		if _, err := parseClock(p.QuietEnd); err != nil {
			return fmt.Errorf("wake config %s: %w", peer, err)
		}
	}
	for _, n := range []int{p.MinInterval, p.PerHour, p.PerDay, p.BreakerFailures, p.BreakerCooldown, p.RetryMax, p.RetryBackoff, p.HopLimit} {
		if n < 0 {
			return fmt.Errorf("wake config %s: numeric fields must be non-negative", peer)
		}
	}
	if p.RetryMax > 5 {
		return fmt.Errorf("wake config %s: retry_max must be at most 5", peer)
	}
	return nil
}

// Decision records one gate evaluation: what was requested, whether the wake
// was effective, and why not if it was suppressed or deferred.
type Decision struct {
	At        float64 `json:"at"`
	Requested bool    `json:"requested"`
	Effective bool    `json:"effective"`
	Reason    string  `json:"reason"`
	Outcome   string  `json:"outcome,omitempty"` // delivered|failed
	Attempts  int     `json:"attempts,omitempty"`
}

// Status is the wake_status snapshot for one peer.
type Status struct {
	Peer                string    `json:"peer"`
	Adapter             string    `json:"adapter"`
	Paused              bool      `json:"paused"`
	Breaker             string    `json:"breaker"` // closed|open|half_open
	ConsecutiveFailures int       `json:"consecutive_failures"`
	Deferred            int       `json:"deferred"`
	Requested           int       `json:"requested"`
	Suppressed          int       `json:"suppressed"`
	Delivered           int       `json:"delivered"`
	Failed              int       `json:"failed"`
	Last                *Decision `json:"last,omitempty"`
}

type peerState struct {
	mu         sync.Mutex
	paused     bool
	failures   int
	openedAt   time.Time
	lastWake   time.Time
	history    []time.Time
	deferred   []Notice
	last       *Decision
	requested  int
	suppressed int
	delivered  int
	failed     int
}

const maxDeferred = 100

// Service evaluates per-peer gates and drives adapters. Peers absent from
// the config are never woken (adapter "none").
type Service struct {
	cfg      Config
	adapters map[string]Adapter

	mu     sync.Mutex
	states map[string]*peerState

	// Now and Sleep are optional test hooks; both default to the real clock.
	Now   func() time.Time
	Sleep func(ctx context.Context, d time.Duration) error
}

// NewService validates the config and builds adapters. MCP-event peers start
// without a sink; attach one with SetSink.
func NewService(cfg Config) (*Service, error) {
	s := &Service{cfg: cfg, adapters: map[string]Adapter{}, states: map[string]*peerState{}}
	for peer, p := range cfg.Peers {
		if err := validate(peer, p); err != nil {
			return nil, err
		}
		switch p.Adapter {
		case "webhook":
			s.adapters[peer] = &Webhook{URL: p.WebhookURL, Secret: p.HMACSecret, Preview: p.Preview}
		case "exec":
			s.adapters[peer] = &Exec{Argv: append([]string{}, p.ExecArgv...)}
		case "mcp-event":
			s.adapters[peer] = EventSink{}
		default:
			s.adapters[peer] = None{}
		}
	}
	return s, nil
}

// SetSink attaches the MCP event sink (P2) for a peer configured with the
// mcp-event adapter.
func (s *Service) SetSink(peer string, sink SinkFunc) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.adapters[peer].(EventSink); !ok {
		return fmt.Errorf("wake: peer %q is not an mcp-event adapter", peer)
	}
	s.adapters[peer] = EventSink{Sink: sink}
	return nil
}

// Pause suspends wakes for a peer until Resume; notices are suppressed, not
// queued.
func (s *Service) Pause(peer string) {
	st := s.state(peer)
	st.mu.Lock()
	st.paused = true
	st.mu.Unlock()
}
func (s *Service) Resume(peer string) {
	st := s.state(peer)
	st.mu.Lock()
	st.paused = false
	st.mu.Unlock()
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) sleep(ctx context.Context, d time.Duration) error {
	if s.Sleep != nil {
		return s.Sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Service) state(peer string) *peerState {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.states[peer]
	if !ok {
		st = &peerState{}
		s.states[peer] = st
	}
	return st
}

// Notify wakes the peer asynchronously; used by the HTTP layer so slow
// adapters never delay a send response.
func (s *Service) Notify(peer string, n Notice) {
	if _, ok := s.cfg.Peers[peer]; !ok {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		s.Wake(ctx, peer, n)
	}()
}

// Wake evaluates the gate for one notice and delivers it if effective.
func (s *Service) Wake(ctx context.Context, peer string, n Notice) Decision {
	cfg, ok := s.cfg.Peers[peer]
	if !ok {
		return Decision{Requested: true, Reason: "no_adapter"}
	}
	st := s.state(peer)
	ad := s.adapters[peer]
	st.mu.Lock()
	defer st.mu.Unlock()
	now := s.now()
	// Quiet hours defer, not drop: retry deferred notices once the window ends.
	if len(st.deferred) > 0 && !quiet(cfg, now) {
		pending := st.deferred
		st.deferred = nil
		for _, d := range pending {
			s.gate(ctx, cfg, ad, st, d, now, false)
		}
	}
	return s.gate(ctx, cfg, ad, st, n, now, true)
}

func quiet(cfg PeerConfig, now time.Time) bool {
	if cfg.QuietStart == "" {
		return false
	}
	start, _ := parseClock(cfg.QuietStart)
	end, _ := parseClock(cfg.QuietEnd)
	local := now.In(time.Local)
	mins := local.Hour()*60 + local.Minute()
	if start <= end {
		return mins >= start && mins < end
	}
	return mins >= start || mins < end
}

func (s *Service) gate(ctx context.Context, cfg PeerConfig, ad Adapter, st *peerState, n Notice, now time.Time, allowDefer bool) Decision {
	d := Decision{At: float64(now.Unix()) + float64(now.Nanosecond())/1e9, Requested: true}
	st.requested++
	suppress := func(reason string) Decision {
		d.Reason = reason
		st.suppressed++
		st.last = &d
		return d
	}
	if st.paused || cfg.Paused {
		return suppress("paused")
	}
	if cfg.HopLimit > 0 && n.Hop > cfg.HopLimit {
		return suppress("hop_limit")
	}
	if quiet(cfg, now) {
		if allowDefer && len(st.deferred) < maxDeferred {
			st.deferred = append(st.deferred, n)
			return suppress("quiet_hours_deferred")
		}
		return suppress("quiet_hours")
	}
	if breakerBlocked(cfg, st, now) {
		return suppress("breaker_open")
	}
	if cfg.MinInterval > 0 && !st.lastWake.IsZero() && now.Sub(st.lastWake) < time.Duration(cfg.MinInterval)*time.Second {
		return suppress("min_interval")
	}
	prune(st, now)
	if cfg.PerHour > 0 && countSince(st.history, now.Add(-time.Hour)) >= cfg.PerHour {
		return suppress("per_hour_cap")
	}
	if cfg.PerDay > 0 && countSince(st.history, now.Add(-24*time.Hour)) >= cfg.PerDay {
		return suppress("per_day_cap")
	}
	d.Effective = true
	d.Reason = "ok"
	if !cfg.Preview {
		n.Preview = ""
	}
	attempts, err := s.deliver(ctx, ad, cfg, n)
	d.Attempts = attempts
	if err != nil {
		d.Outcome = "failed"
		st.failed++
		st.failures++
		if cfg.BreakerFailures > 0 && st.failures >= cfg.BreakerFailures {
			st.openedAt = now
		}
	} else {
		d.Outcome = "delivered"
		st.delivered++
		st.failures = 0
		st.openedAt = time.Time{}
		st.lastWake = now
		st.history = append(st.history, now)
	}
	st.last = &d
	return d
}

func breakerBlocked(cfg PeerConfig, st *peerState, now time.Time) bool {
	if cfg.BreakerFailures <= 0 || st.failures < cfg.BreakerFailures {
		return false
	}
	cooldown := cfg.BreakerCooldown
	if cooldown <= 0 {
		cooldown = 60
	}
	return now.Sub(st.openedAt) < time.Duration(cooldown)*time.Second
}

func prune(st *peerState, now time.Time) {
	cutoff := now.Add(-24 * time.Hour)
	keep := st.history[:0]
	for _, t := range st.history {
		if t.After(cutoff) {
			keep = append(keep, t)
		}
	}
	st.history = keep
}

func countSince(history []time.Time, cutoff time.Time) int {
	n := 0
	for _, t := range history {
		if t.After(cutoff) || t.Equal(cutoff) {
			n++
		}
	}
	return n
}

// deliver retries the adapter with bounded doubling backoff.
func (s *Service) deliver(ctx context.Context, ad Adapter, cfg PeerConfig, n Notice) (int, error) {
	max := 1 + cfg.RetryMax
	backoff := cfg.RetryBackoff
	if backoff <= 0 {
		backoff = 1
	}
	var err error
	for attempt := 1; attempt <= max; attempt++ {
		if err = ad.Wake(ctx, n); err == nil {
			return attempt, nil
		}
		if attempt < max {
			if e := s.sleep(ctx, time.Duration(backoff<<(attempt-1))*time.Second); e != nil {
				return attempt, err
			}
		}
	}
	return max, err
}

// Status reports the current gate snapshot for a peer.
func (s *Service) Status(peer string) Status {
	cfg, ok := s.cfg.Peers[peer]
	adapter := "none"
	if ok && cfg.Adapter != "" {
		adapter = cfg.Adapter
	}
	st := s.state(peer)
	st.mu.Lock()
	defer st.mu.Unlock()
	breaker := "closed"
	if ok && cfg.BreakerFailures > 0 && st.failures >= cfg.BreakerFailures {
		if breakerBlocked(cfg, st, s.now()) {
			breaker = "open"
		} else {
			breaker = "half_open"
		}
	}
	return Status{
		Peer: peer, Adapter: adapter, Paused: st.paused || cfg.Paused,
		Breaker: breaker, ConsecutiveFailures: st.failures, Deferred: len(st.deferred),
		Requested: st.requested, Suppressed: st.suppressed, Delivered: st.delivered,
		Failed: st.failed, Last: st.last,
	}
}
