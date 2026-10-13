// Package events implements MCP event subscriptions (message.created) with
// signed webhook callback delivery, ported generically from dot-bridge's
// events.py: Standard Webhooks v1 signatures, callback verification with a
// single-use challenge, deterministic idempotent subscription IDs, a durable
// bbolt outbox with bounded retry/backoff, no retry on 410/413, a 256 KiB
// body cap, HTTPS-only callbacks to allow-listed hosts on public IPs, and no
// redirects. Default off: serve wires it only with --mcp.
package events

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
)

// CallbackEndpointError is the JSON-RPC error code for a callback endpoint
// failure during subscribe.
const CallbackEndpointError = -32015

const (
	MaxBody              = 256 * 1024
	DefaultTTLMS         = 7 * 24 * 3600 * 1000
	MinTTLMS             = 3600 * 1000
	VerifyCacheSeconds   = 24 * 3600
	RotationWindowSecond = 24 * 3600
)

// RetryDelays are the seconds between delivery attempts; after the last one
// an entry is marked failed.
var RetryDelays = []float64{30, 120, 600, 1800, 3600, 7200}

// EventName is the only event: a new message for the MCP peer.
const EventName = "message.created"

// EventDef is the events/list descriptor.
var EventDef = map[string]any{
	"name": EventName,
	"description": "A new Relaynote message addressed to this peer arrived. The payload is only a " +
		"wake-up summary; read the full message with read_messages(message_id=...).",
	"delivery":      []string{"webhook"},
	"inputSchema":   map[string]any{"type": "object", "properties": map[string]any{}, "additionalProperties": false},
	"payloadSchema": payloadSchema(),
}

func payloadSchema() map[string]any {
	str := map[string]any{"type": "string"}
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"message_id":      str,
			"conversation_id": str,
			"from":            str,
			"kind":            map[string]any{"type": "string", "enum": []string{"chat", "notice"}},
			"hop":             map[string]any{"type": "integer"},
			"reply_allowed":   map[string]any{"type": "boolean"},
			"preview":         str,
			"created_at":      str,
		},
		"required": []string{"message_id", "conversation_id", "from", "kind", "hop", "reply_allowed",
			"preview", "created_at"},
		"additionalProperties": false,
	}
}

// CallbackError rejects a callback URL or delivery with a machine reason.
type CallbackError struct{ Reason string }

func (e *CallbackError) Error() string { return e.Reason }

// InvalidParams maps to JSON-RPC -32602.
type InvalidParams struct{ Message string }

func (e *InvalidParams) Error() string { return e.Message }

func invalidParams(format string, args ...any) *InvalidParams {
	return &InvalidParams{Message: fmt.Sprintf(format, args...)}
}

// ValidSecret checks the whsec_ base64 (24-64 bytes) signing secret shape.
func ValidSecret(secret string) bool {
	if !strings.HasPrefix(secret, "whsec_") {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(secret[6:])
	return err == nil && len(raw) >= 24 && len(raw) <= 64
}

// Sign produces the Standard Webhooks v1 signature header value.
func Sign(secret, msgID string, ts int64, body string) string {
	key, _ := base64.StdEncoding.DecodeString(secret[6:])
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(fmt.Sprintf("%s.%d.%s", msgID, ts, body)))
	return "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// VerifySignature is the receiver-side check, used by tests and fake
// receivers.
func VerifySignature(secret string, headers http.Header, body []byte, tolerance int64, now time.Time) bool {
	ts, err := strconv.ParseInt(headers.Get("webhook-timestamp"), 10, 64)
	if err != nil {
		return false
	}
	if abs(now.Unix()-ts) > tolerance {
		return false
	}
	expected := Sign(secret, headers.Get("webhook-id"), ts, string(body))
	expected = strings.SplitN(expected, ",", 2)[1]
	for _, part := range strings.Fields(headers.Get("webhook-signature")) {
		if strings.HasPrefix(part, "v1,") && subtle.ConstantTimeCompare([]byte(part[3:]), []byte(expected)) == 1 {
			return true
		}
	}
	return false
}

func abs(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}

// HostAllowed matches exact names or "*.example.com" (suffix match, not glob).
func HostAllowed(host string, patterns []string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, p := range patterns {
		p = strings.ToLower(p)
		if strings.HasPrefix(p, "*.") {
			if strings.HasSuffix(host, p[1:]) && len(host) > len(p)-1 {
				return true
			}
		} else if host == p {
			return true
		}
	}
	return false
}

// SafeHTTP posts to callbacks with SSRF defenses: HTTPS only (unless
// AllowInsecure for tests), allow-listed hostnames, public IPs resolved and
// pinned at connect time, no redirects, bounded response reads.
type SafeHTTP struct {
	HostAllow     []string
	AllowInsecure bool // tests only: also permits http, any port, any host
	Timeout       time.Duration
}

// CheckURL validates a callback URL without connecting.
func (h *SafeHTTP) CheckURL(rawurl string) (*url.URL, error) {
	if len(rawurl) == 0 || len(rawurl) > 2048 {
		return nil, &CallbackError{"invalid_url"}
	}
	u, err := url.Parse(rawurl)
	if err != nil {
		return nil, &CallbackError{"invalid_url"}
	}
	if u.Scheme != "https" && !(h.AllowInsecure && u.Scheme == "http") {
		return nil, &CallbackError{"insecure_url"}
	}
	if u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return nil, &CallbackError{"invalid_url"}
	}
	if !h.AllowInsecure && !HostAllowed(u.Hostname(), h.HostAllow) {
		return nil, &CallbackError{"host_not_allowed"}
	}
	if p := u.Port(); p != "" {
		if !h.AllowInsecure && p != "443" {
			return nil, &CallbackError{"port_not_allowed"}
		}
		if n, err := net.LookupPort("tcp", p); err != nil || n <= 0 || n > 65535 {
			return nil, &CallbackError{"invalid_url"}
		}
	}
	return u, nil
}

// resolve picks one publicly routable IP for the host.
func (h *SafeHTTP) resolve(ctx context.Context, host string) (string, error) {
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return "", &CallbackError{"dns_failure"}
	}
	for _, ip := range ips {
		if h.AllowInsecure || (ip.IsGlobalUnicast() && !ip.IsMulticast()) {
			return ip.String(), nil
		}
	}
	return "", &CallbackError{"blocked_address"}
}

func (h *SafeHTTP) client() *http.Client {
	timeout := h.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	dialer := &net.Dialer{Timeout: timeout}
	transport := &http.Transport{
		// Resolve and pin the IP: the TCP connection goes to the address we
		// validated, so DNS cannot change between check and connect.
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ip, err := h.resolve(ctx, host)
			if err != nil {
				return nil, err
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(ip, port))
		},
	}
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// Post delivers body to url and returns the status code and a bounded read
// of the response body.
func (h *SafeHTTP) Post(ctx context.Context, rawurl string, body []byte, headers map[string]string) (int, []byte, error) {
	u, err := h.CheckURL(rawurl)
	if err != nil {
		return 0, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return 0, nil, &CallbackError{"invalid_url"}
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := h.client().Do(req)
	if err != nil {
		var ce *CallbackError
		if errors.As(err, &ce) {
			return 0, nil, ce
		}
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return 0, nil, &CallbackError{"timeout"}
		}
		if nerr, ok := err.(*url.Error); ok && nerr.Timeout() {
			return 0, nil, &CallbackError{"timeout"}
		}
		return 0, nil, &CallbackError{"connection_failed"}
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return resp.StatusCode, nil, &CallbackError{"connection_failed"}
	}
	return resp.StatusCode, data, nil
}

// ------------------------------------------------------------------ service

var (
	bucketSubs     = []byte("event_subscriptions")
	bucketVerified = []byte("event_verified_callbacks")
	bucketOutbox   = []byte("event_outbox")
)

type subscription struct {
	ID             string   `json:"id"`
	Principal      string   `json:"principal"`
	Name           string   `json:"name"`
	Arguments      string   `json:"arguments"` // canonical JSON
	URL            string   `json:"url"`
	Secret         string   `json:"secret"`
	OldSecret      string   `json:"old_secret,omitempty"`
	OldSecretUntil float64  `json:"old_secret_until,omitempty"`
	ExpiresAt      *float64 `json:"expires_at"`
	CreatedAt      float64  `json:"created_at"`
	UpdatedAt      float64  `json:"updated_at"`
}

type outboxEntry struct {
	EventID        string  `json:"event_id"`
	SubscriptionID string  `json:"subscription_id"`
	Body           string  `json:"body"`
	Attempts       int     `json:"attempts"`
	NextAttemptAt  float64 `json:"next_attempt_at"`
	Status         string  `json:"status"` // pending|delivered|failed|cancelled
	LastResult     string  `json:"last_result,omitempty"`
	CreatedAt      float64 `json:"created_at"`
}

// Service manages subscriptions and the delivery outbox.
type Service struct {
	db   *bolt.DB
	http *SafeHTTP

	// Now is an optional clock for deterministic tests.
	Now func() time.Time
}

// New returns the events service on the hub database.
func New(db *bolt.DB, http *SafeHTTP) *Service {
	return &Service{db: db, http: http}
}

func (s *Service) now() float64 {
	t := time.Now()
	if s.Now != nil {
		t = s.Now()
	}
	return float64(t.Unix()) + float64(t.Nanosecond())/1e9
}

func canonical(v any) (string, error) {
	// Python's canonical JSON: sorted keys, no spaces, no ASCII escaping.
	buf := &bytes.Buffer{}
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return "", err
	}
	return strings.TrimSuffix(buf.String(), "\n"), nil
}

func utcISO(ts float64) string {
	sec := int64(ts)
	nsec := int64((ts - float64(sec)) * 1e9)
	return time.Unix(sec, nsec).UTC().Format("2006-01-02T15:04:05Z")
}

// SubscriptionID is deterministic: the same principal+url+name+args always
// yields the same subscription.
func SubscriptionID(principal, rawurl, name string, args map[string]any) string {
	c, _ := canonical([]any{principal, rawurl, name, args})
	sum := sha256.Sum256([]byte(c))
	return "sub_" + hex.EncodeToString(sum[:])[:32]
}

func vkey(rawurl, secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return rawurl + "#" + hex.EncodeToString(sum[:])[:16]
}

// ListEvents implements events/list.
func (s *Service) ListEvents(principal string, params map[string]any) map[string]any {
	return map[string]any{"events": []any{EventDef}}
}

type parsedSubscribe struct {
	name   string
	args   map[string]any
	url    string
	secret string
}

func parseParams(params map[string]any) (*parsedSubscribe, error) {
	if params == nil {
		return nil, invalidParams("params must be an object")
	}
	if params["name"] != EventName {
		return nil, invalidParams("Unknown event name")
	}
	args, _ := params["arguments"].(map[string]any)
	if params["arguments"] != nil && args == nil || len(args) > 0 {
		return nil, invalidParams("message.created takes no arguments")
	}
	delivery, _ := params["delivery"].(map[string]any)
	if delivery == nil || delivery["mode"] != "webhook" {
		return nil, invalidParams("delivery.mode must be webhook with a url")
	}
	rawurl, ok := delivery["url"].(string)
	if !ok {
		return nil, invalidParams("delivery.mode must be webhook with a url")
	}
	secret, _ := delivery["secret"].(string)
	if !ValidSecret(secret) {
		return nil, invalidParams("delivery.secret must be whsec_ followed by base64 of 24 to 64 bytes")
	}
	return &parsedSubscribe{name: EventName, args: map[string]any{}, url: rawurl, secret: secret}, nil
}

func (s *Service) grantExpiry(requested any) (float64, error) {
	ttl := float64(DefaultTTLMS)
	switch v := requested.(type) {
	case nil:
		// ttlMs:null asks for no expiry; we grant a finite one.
	case float64:
		if v <= 0 {
			return 0, invalidParams("ttlMs must be a positive number of milliseconds or null")
		}
		ttl = v
		if ttl < MinTTLMS {
			ttl = MinTTLMS
		}
		if ttl > DefaultTTLMS {
			ttl = DefaultTTLMS
		}
	default:
		return 0, invalidParams("ttlMs must be a positive number of milliseconds or null")
	}
	return s.now() + ttl/1000, nil
}

// Subscribe implements events/subscribe: verifies the callback with a
// single-use signed challenge (cached per URL+secret for a day), then upserts
// the deterministic subscription.
func (s *Service) Subscribe(principal string, params map[string]any) (map[string]any, error) {
	p, err := parseParams(params)
	if err != nil {
		return nil, err
	}
	if _, err := s.http.CheckURL(p.url); err != nil {
		return nil, err
	}
	subID := SubscriptionID(principal, p.url, p.name, p.args)
	var requested any
	if raw, ok := params["ttlMs"]; ok {
		requested = raw
	}
	expiresAt, err := s.grantExpiry(requested)
	if err != nil {
		return nil, err
	}
	var existing *subscription
	verified := false
	err = s.db.View(func(tx *bolt.Tx) error {
		if data := tx.Bucket(bucketSubs).Get([]byte(subID)); data != nil {
			var sub subscription
			if err := json.Unmarshal(data, &sub); err != nil {
				return err
			}
			existing = &sub
		}
		data := tx.Bucket(bucketVerified).Get([]byte(principal + "\x00" + vkey(p.url, p.secret)))
		if data != nil {
			var ts float64
			if err := json.Unmarshal(data, &ts); err != nil {
				return err
			}
			verified = s.now()-ts < VerifyCacheSeconds
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if !verified {
		if err := s.verifyCallback(context.Background(), subID, p.url, p.secret); err != nil {
			return nil, err
		}
	}
	now := s.now()
	err = s.db.Update(func(tx *bolt.Tx) error {
		if err := putJSON(tx.Bucket(bucketVerified), []byte(principal+"\x00"+vkey(p.url, p.secret)), now); err != nil {
			return err
		}
		b := tx.Bucket(bucketSubs)
		if existing != nil {
			rotating := existing.Secret != p.secret
			sub := *existing
			sub.Secret = p.secret
			if rotating {
				sub.OldSecret = existing.Secret
				sub.OldSecretUntil = now + RotationWindowSecond
			}
			sub.ExpiresAt = &expiresAt
			sub.UpdatedAt = now
			return putJSON(b, []byte(subID), sub)
		}
		argsCanonical, err := canonical(p.args)
		if err != nil {
			return err
		}
		return putJSON(b, []byte(subID), subscription{
			ID: subID, Principal: principal, Name: p.name, Arguments: argsCanonical,
			URL: p.url, Secret: p.secret, ExpiresAt: &expiresAt, CreatedAt: now, UpdatedAt: now,
		})
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"id": subID, "refreshBefore": utcISO(expiresAt), "cursor": nil, "truncated": false}, nil
}

// Unsubscribe implements events/unsubscribe and cancels its pending outbox
// entries.
func (s *Service) Unsubscribe(principal string, params map[string]any) (map[string]any, error) {
	p, err := parseParams(params)
	if err != nil {
		return nil, err
	}
	subID := SubscriptionID(principal, p.url, p.name, p.args)
	err = s.db.Update(func(tx *bolt.Tx) error {
		subs := tx.Bucket(bucketSubs)
		if data := subs.Get([]byte(subID)); data != nil {
			var sub subscription
			if err := json.Unmarshal(data, &sub); err != nil {
				return err
			}
			if sub.Principal == principal {
				if err := subs.Delete([]byte(subID)); err != nil {
					return err
				}
			}
		}
		return s.cancelPending(tx, subID)
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{}, nil
}

func (s *Service) cancelPending(tx *bolt.Tx, subID string) error {
	b := tx.Bucket(bucketOutbox)
	return b.ForEach(func(k, v []byte) error {
		var e outboxEntry
		if err := json.Unmarshal(v, &e); err != nil {
			return err
		}
		if e.SubscriptionID == subID && e.Status == "pending" {
			e.Status = "cancelled"
			return putJSON(b, append([]byte{}, k...), e)
		}
		return nil
	})
}

func (s *Service) verifyCallback(ctx context.Context, subID, rawurl, secret string) error {
	challenge, err := randomString(32)
	if err != nil {
		return err
	}
	rnd := make([]byte, 8)
	if _, err := rand.Read(rnd); err != nil {
		return err
	}
	msgID := "msg_verification_" + hex.EncodeToString(rnd)
	body, err := canonical(map[string]any{"type": "verification", "challenge": challenge})
	if err != nil {
		return err
	}
	ts := int64(s.now())
	headers := map[string]string{
		"Content-Type": "application/json", "webhook-id": msgID,
		"webhook-timestamp":     fmt.Sprintf("%d", ts),
		"webhook-signature":     Sign(secret, msgID, ts, body),
		"X-MCP-Subscription-Id": subID,
	}
	status, data, err := s.http.Post(ctx, rawurl, []byte(body), headers)
	if err != nil {
		return err
	}
	if status < 200 || status > 299 {
		return &CallbackError{"challenge_failed"}
	}
	var echoed struct {
		Challenge string `json:"challenge"`
	}
	if err := json.Unmarshal(data, &echoed); err != nil {
		return &CallbackError{"challenge_failed"}
	}
	if echoed.Challenge == "" || subtle.ConstantTimeCompare([]byte(echoed.Challenge), []byte(challenge)) != 1 {
		return &CallbackError{"challenge_failed"}
	}
	return nil
}

// ActiveCount reports the number of unexpired subscriptions.
func (s *Service) ActiveCount() int {
	n := 0
	now := s.now()
	_ = s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketSubs).ForEach(func(_, v []byte) error {
			var sub subscription
			if err := json.Unmarshal(v, &sub); err != nil {
				return err
			}
			if sub.ExpiresAt == nil || *sub.ExpiresAt > now {
				n++
			}
			return nil
		})
	})
	return n
}

// PublishData is the message.created payload; the wake layer fills it from a
// wake.Notice.
type PublishData map[string]any

// Publish enqueues one signed event per active subscription; returns the
// number queued.
func (s *Service) Publish(data PublishData, eventID string, occurredAt float64) (int, error) {
	now := s.now()
	queued := 0
	err := s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketSubs).ForEach(func(_, v []byte) error {
			var sub subscription
			if err := json.Unmarshal(v, &sub); err != nil {
				return err
			}
			if sub.ExpiresAt != nil && *sub.ExpiresAt <= now {
				return nil
			}
			body, err := canonical(map[string]any{
				"eventId": eventID, "name": EventName, "timestamp": utcISO(occurredAt),
				"data": map[string]any(data), "cursor": nil,
			})
			if err != nil {
				return err
			}
			if len(body) > MaxBody {
				return errors.New("event body too large")
			}
			key := []byte(eventID + "\x00" + sub.ID)
			if tx.Bucket(bucketOutbox).Get(key) != nil {
				return nil // INSERT OR IGNORE
			}
			queued++
			return putJSON(tx.Bucket(bucketOutbox), key, outboxEntry{
				EventID: eventID, SubscriptionID: sub.ID, Body: body,
				NextAttemptAt: now, Status: "pending", CreatedAt: now,
			})
		})
	})
	return queued, err
}

// DeliverStats summarizes one DeliverDue pass.
type DeliverStats struct {
	Delivered int `json:"delivered"`
	Retrying  int `json:"retrying"`
	Failed    int `json:"failed"`
}

// DeliverDue delivers every pending outbox entry whose time has come,
// applying retry/backoff, the 410/413 no-retry rule and subscription
// deletion on 410.
func (s *Service) DeliverDue(ctx context.Context) (DeliverStats, error) {
	now := s.now()
	if err := s.Purge(now); err != nil {
		return DeliverStats{}, err
	}
	var due []struct {
		key []byte
		in  outboxEntry
		sub subscription
	}
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketOutbox).ForEach(func(k, v []byte) error {
			var e outboxEntry
			if err := json.Unmarshal(v, &e); err != nil {
				return err
			}
			if e.Status != "pending" || e.NextAttemptAt > now {
				return nil
			}
			data := tx.Bucket(bucketSubs).Get([]byte(e.SubscriptionID))
			if data == nil {
				return nil // orphaned; purge cancels on the next pass
			}
			var sub subscription
			if err := json.Unmarshal(data, &sub); err != nil {
				return err
			}
			due = append(due, struct {
				key []byte
				in  outboxEntry
				sub subscription
			}{append([]byte{}, k...), e, sub})
			return nil
		})
	})
	if err != nil {
		return DeliverStats{}, err
	}
	stats := DeliverStats{}
	for _, row := range due {
		status, outcome := s.send(ctx, &row.sub, &row.in)
		attempts := row.in.Attempts + 1
		err := s.db.Update(func(tx *bolt.Tx) error {
			b := tx.Bucket(bucketOutbox)
			e := row.in
			e.Attempts = attempts
			e.LastResult = outcome
			if status >= 200 && status <= 299 {
				e.Status = "delivered"
				stats.Delivered++
				return putJSON(b, row.key, e)
			}
			if status == 410 {
				if err := tx.Bucket(bucketSubs).Delete([]byte(row.sub.ID)); err != nil {
					return err
				}
			}
			final := status == 410 || status == 413 || attempts > len(RetryDelays)
			if final {
				e.Status = "failed"
				stats.Failed++
			} else {
				e.NextAttemptAt = now + RetryDelays[attempts-1]
				stats.Retrying++
			}
			return putJSON(b, row.key, e)
		})
		if err != nil {
			return stats, err
		}
	}
	return stats, nil
}

func (s *Service) send(ctx context.Context, sub *subscription, e *outboxEntry) (int, string) {
	ts := int64(s.now())
	sig := Sign(sub.Secret, e.EventID, ts, e.Body)
	if sub.OldSecret != "" && sub.OldSecretUntil > s.now() {
		sig += " " + Sign(sub.OldSecret, e.EventID, ts, e.Body)
	}
	headers := map[string]string{
		"Content-Type": "application/json", "webhook-id": e.EventID,
		"webhook-timestamp":     fmt.Sprintf("%d", ts),
		"webhook-signature":     sig,
		"X-MCP-Subscription-Id": sub.ID,
	}
	status, _, err := s.http.Post(ctx, sub.URL, []byte(e.Body), headers)
	if err != nil {
		var ce *CallbackError
		if errors.As(err, &ce) {
			return 0, ce.Reason
		}
		return 0, "connection_failed"
	}
	return status, fmt.Sprintf("%d", status)
}

// Purge drops expired subscriptions, cancels their pending entries and
// orphaned ones, and expires the verification cache and old outbox rows.
func (s *Service) Purge(now float64) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		subs := tx.Bucket(bucketSubs)
		var expired []string
		err := subs.ForEach(func(k, v []byte) error {
			var sub subscription
			if err := json.Unmarshal(v, &sub); err != nil {
				return err
			}
			if sub.ExpiresAt != nil && *sub.ExpiresAt <= now {
				expired = append(expired, sub.ID)
			}
			return nil
		})
		if err != nil {
			return err
		}
		for _, id := range expired {
			if err := subs.Delete([]byte(id)); err != nil {
				return err
			}
			if err := s.cancelPending(tx, id); err != nil {
				return err
			}
		}
		outbox := tx.Bucket(bucketOutbox)
		var doomed [][]byte
		err = outbox.ForEach(func(k, v []byte) error {
			var e outboxEntry
			if err := json.Unmarshal(v, &e); err != nil {
				return err
			}
			if e.Status == "pending" && subs.Get([]byte(e.SubscriptionID)) == nil {
				e.Status = "cancelled"
				return putJSON(outbox, append([]byte{}, k...), e)
			}
			if e.Status != "pending" && e.CreatedAt < now-7*86400 {
				doomed = append(doomed, append([]byte{}, k...))
			}
			return nil
		})
		if err != nil {
			return err
		}
		for _, k := range doomed {
			if err := outbox.Delete(k); err != nil {
				return err
			}
		}
		verified := tx.Bucket(bucketVerified)
		doomed = nil
		err = verified.ForEach(func(k, v []byte) error {
			var ts float64
			if err := json.Unmarshal(v, &ts); err != nil {
				return err
			}
			if ts < now-VerifyCacheSeconds {
				doomed = append(doomed, append([]byte{}, k...))
			}
			return nil
		})
		if err != nil {
			return err
		}
		for _, k := range doomed {
			if err := verified.Delete(k); err != nil {
				return err
			}
		}
		return nil
	})
}

// RunDeliverLoop calls DeliverDue every interval until ctx ends; serve uses
// it for retries, while first attempts already happen synchronously at
// publish time.
func (s *Service) RunDeliverLoop(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_, _ = s.DeliverDue(ctx)
		}
	}
}

func putJSON(b *bolt.Bucket, key []byte, value any) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return b.Put(key, encoded)
}

func randomString(size int) (string, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
