// Package store implements Relaynote's durable, transactional message queue.
// A successful Send or Ack has committed to disk before returning. Delivery is
// at least once: consumers must make their own side effects idempotent by ID.
package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	bolt "go.etcd.io/bbolt"
)

const (
	DefaultTTL = 604800
	MaxTTL     = 2592000
	MaxBody    = 65536
)

var (
	peersBucket    = []byte("peers")
	tokensBucket   = []byte("tokens")
	messagesBucket = []byte("messages")
	dedupeBucket   = []byte("dedupe")
	inboxesBucket  = []byte("inboxes")
	metadataBucket = []byte("metadata")
	requestsBucket = []byte("requests")
	// Buckets for the opt-in P2 layers (internal/oauth and internal/events).
	// They are created alongside the core buckets so one database file holds
	// all hub state; with the serve flags off they simply stay empty.
	oauthClientsBucket  = []byte("oauth_clients")
	oauthRequestsBucket = []byte("oauth_requests")
	oauthCodesBucket    = []byte("oauth_codes")
	oauthTokensBucket   = []byte("oauth_tokens")
	oauthKVBucket       = []byte("oauth_kv")
	oauthDevicesBucket  = []byte("oauth_devices")
	oauthFailuresBucket = []byte("oauth_login_failures")
	eventSubsBucket     = []byte("event_subscriptions")
	eventVerifiedBucket = []byte("event_verified_callbacks")
	eventOutboxBucket   = []byte("event_outbox")
	namePattern         = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,64}$`)
	idPattern           = regexp.MustCompile(`^[a-zA-Z0-9_.:-]{1,128}$`)
	tokenPattern        = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	receiptPattern      = regexp.MustCompile(`^[A-Za-z0-9_-]{32}$`)
)

// Error is a request error whose Status may be exposed by the HTTP layer.
// Infrastructure errors are returned separately and must not be exposed there.
type Error struct {
	Status  int
	Message string
}

func (e *Error) Error() string { return e.Message }

func requestError(status int, message string) error {
	return &Error{Status: status, Message: message}
}

// SendRequest contains only user-controlled message fields. TTL must be explicit
// here; the HTTP layer applies DefaultTTL when the field is absent.
type SendRequest struct {
	To       string `json:"to"`
	Body     string `json:"body"`
	ClientID string `json:"client_id"`
	TTL      int    `json:"ttl"`
	// Optional native envelope fields (P0); accepted by the HTTP layer only
	// when its envelope option is enabled.
	Kind string `json:"kind,omitempty"`
	Conv string `json:"conv,omitempty"`
	Hop  int    `json:"hop,omitempty"`
}

// Message is the public wire representation. Receipt and LeaseUntil are exposed
// only to the authenticated recipient on Claim, never on Send, Get, or Ack.
type Message struct {
	ID            string   `json:"id"`
	Sender        string   `json:"sender"`
	Recipient     string   `json:"recipient"`
	ClientID      string   `json:"client_id"`
	ThreadID      string   `json:"thread_id"`
	ReplyTo       *string  `json:"reply_to"`
	Kind          string   `json:"kind,omitempty"`
	Conv          string   `json:"conv,omitempty"`
	Hop           int      `json:"hop,omitempty"`
	Body          string   `json:"body"`
	CreatedAt     float64  `json:"created_at"`
	ExpiresAt     float64  `json:"expires_at"`
	AckedAt       *float64 `json:"acked_at"`
	Attempts      int      `json:"attempts"`
	State         string   `json:"state"`
	AgentAwakened string   `json:"agent_awakened"`
	Receipt       string   `json:"receipt,omitempty"`
	LeaseUntil    float64  `json:"lease_until,omitempty"`
	// Created is set by Send when the message was newly persisted (never on an
	// idempotent replay). It is internal-only and never serialized.
	Created bool `json:"-"`
}

type peer struct {
	Name      string   `json:"name"`
	TokenHash string   `json:"token_hash"`
	Allowed   []string `json:"allowed"`
	Enabled   bool     `json:"enabled"`
}

type record struct {
	Message     Message `json:"message"`
	Fingerprint string  `json:"fingerprint"`
	Receipt     string  `json:"receipt"`
	LeaseUntil  float64 `json:"lease_until"`
	Sequence    uint64  `json:"sequence"`
}

// Store owns an exclusive bbolt database lock. Stop the relay before opening
// the same database in an administrative CLI command or another process.
type Store struct {
	db *bolt.DB

	// Now is an optional clock for deterministic tests. Set it before concurrent
	// use; the supplied function itself must be safe for concurrent calls.
	Now func() time.Time

	// Lifecycle opts in to request lifecycle tracking (P0): Send of a message
	// with Kind "request" then also opens a Request record, and StartRequest,
	// CompleteRequest and GetRequest become available. Default off.
	Lifecycle bool

	// notify is closed and replaced on every committed new message, waking
	// any WaitInbox long-polls.
	notifyMu sync.Mutex
	notify   chan struct{}
}

// New opens a durable queue in a trusted, private directory. The final directory
// and database must not be symlinks. POSIX permissions are enforced where they
// exist; on Windows the caller must provide a directory protected by user-only
// ACLs. Ancestor directories must be trusted against replacement by other users.
func New(path string) (*Store, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("database path is required")
	}
	path = filepath.Clean(path)
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create state directory: %w", err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, fmt.Errorf("inspect state directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, errors.New("state directory must be a real directory, not a symlink")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("state directory must be private (mode 0700)")
	}
	info, err = os.Lstat(path)
	if err == nil && !info.Mode().IsRegular() {
		return nil, errors.New("database must be a regular file, not a symlink")
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect database: %w", err)
	}
	// Directory privacy is checked before either opening or tightening the file.
	// This deliberately avoids platform-specific O_NOFOLLOW constants.
	db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, fmt.Errorf("open database (stop any process using it first): %w", err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("make database private: %w", err)
	}
	s := &Store{db: db, notify: make(chan struct{})}
	err = db.Update(func(tx *bolt.Tx) error {
		meta, err := tx.CreateBucketIfNotExists(metadataBucket)
		if err != nil {
			return err
		}
		version := meta.Get([]byte("schema"))
		if version != nil && string(version) != "1" {
			return fmt.Errorf("unsupported database schema %q", version)
		}
		for _, name := range [][]byte{peersBucket, tokensBucket, messagesBucket, dedupeBucket, inboxesBucket, requestsBucket,
			oauthClientsBucket, oauthRequestsBucket, oauthCodesBucket, oauthTokensBucket, oauthKVBucket,
			oauthDevicesBucket, oauthFailuresBucket, eventSubsBucket, eventVerifiedBucket, eventOutboxBucket} {
			if _, err := tx.CreateBucketIfNotExists(name); err != nil {
				return err
			}
		}
		return meta.Put([]byte("schema"), []byte("1"))
	})
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("initialize database: %w", err)
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

// NewReadOnly opens the database in shared read-only mode, so diagnostics can
// run alongside a live hub. It never creates buckets or modifies the file.
func NewReadOnly(path string) (*Store, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("database path is required")
	}
	path = filepath.Clean(path)
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect database: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("database must be a regular file, not a symlink")
	}
	db, err := bolt.Open(path, 0600, &bolt.Options{ReadOnly: true, Timeout: time.Second})
	if err != nil {
		return nil, fmt.Errorf("open database read-only: %w", err)
	}
	return &Store{db: db, notify: make(chan struct{})}, nil
}

// PeerInfo is the administrative view of one peer used by diagnostics.
type PeerInfo struct {
	Name    string
	Allowed []string
	Enabled bool
}

// PeerInfo returns the peer's enabled state and ACL edges. found is false
// when no such peer exists.
func (s *Store) PeerInfo(name string) (info PeerInfo, found bool, err error) {
	err = s.db.View(func(tx *bolt.Tx) error {
		p, err := loadPeer(tx, name)
		if err != nil {
			return err
		}
		if p == nil {
			return nil
		}
		found = true
		info = PeerInfo{Name: p.Name, Allowed: append([]string{}, p.Allowed...), Enabled: p.Enabled}
		return nil
	})
	return info, found, err
}

// DB exposes the underlying bbolt database for the opt-in P2 layers
// (internal/oauth and internal/events), which keep their state in their own
// buckets of the same file. Callers must treat it as read/write only through
// those packages; the bucket names above are reserved.
func (s *Store) DB() *bolt.DB { return s.db }

// NewToken generates a 256-bit URL-safe bearer token. Only its SHA-256 digest is
// persisted by Provision and Manage; the caller controls secure token delivery.
func NewToken() (string, error) { return randomString(32) }

func randomString(size int) (string, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func messageID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}

func digest(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

func validName(value string) error {
	if !namePattern.MatchString(value) {
		return requestError(400, "invalid node name")
	}
	return nil
}

func validAllowed(allowed []string) error {
	if len(allowed) > 100 {
		return requestError(400, "allowed must be a list of at most 100 names")
	}
	for _, name := range allowed {
		if name != "*" {
			if err := validName(name); err != nil {
				return err
			}
		}
	}
	return nil
}

func validProvisionToken(token string) error {
	if !tokenPattern.MatchString(token) {
		return requestError(400, "token must contain 43 URL-safe characters; use NewToken")
	}
	return nil
}

func putJSON(bucket *bolt.Bucket, key []byte, value any) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return bucket.Put(key, encoded)
}

func loadPeer(tx *bolt.Tx, name string) (*peer, error) {
	data := tx.Bucket(peersBucket).Get([]byte(name))
	if data == nil {
		return nil, nil
	}
	var p peer
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("decode node: %w", err)
	}
	return &p, nil
}

func authenticate(tx *bolt.Tx, token string) (*peer, error) {
	invalid := func() (*peer, error) { return nil, requestError(401, "invalid or revoked token") }
	if !tokenPattern.MatchString(token) {
		return invalid()
	}
	hash := digest(token)
	name := tx.Bucket(tokensBucket).Get([]byte(hash))
	if name == nil {
		return invalid()
	}
	p, err := loadPeer(tx, string(name))
	if err != nil {
		return nil, err
	}
	if p == nil || !p.Enabled || subtle.ConstantTimeCompare([]byte(p.TokenHash), []byte(hash)) != 1 {
		return invalid()
	}
	return p, nil
}

// Provision creates a new peer. Reprovisioning and duplicate tokens are rejected
// rather than silently changing credentials or overwriting an existing peer.
func (s *Store) Provision(name string, allowed []string, token string) error {
	if err := validName(name); err != nil {
		return err
	}
	if err := validAllowed(allowed); err != nil {
		return err
	}
	if err := validProvisionToken(token); err != nil {
		return err
	}
	p := peer{Name: name, TokenHash: digest(token), Allowed: append([]string{}, allowed...), Enabled: true}
	return s.db.Update(func(tx *bolt.Tx) error {
		peers, tokens := tx.Bucket(peersBucket), tx.Bucket(tokensBucket)
		if peers.Get([]byte(name)) != nil {
			return requestError(409, "node exists; use rotate or permissions")
		}
		if tokens.Get([]byte(p.TokenHash)) != nil {
			return requestError(409, "token already assigned to a node")
		}
		if err := putJSON(peers, []byte(name), &p); err != nil {
			return err
		}
		return tokens.Put([]byte(p.TokenHash), []byte(name))
	})
}

// Manage applies one local administrative operation: rotate, revoke, or
// permissions. Rotating a revoked peer re-enables it, as in the Python baseline.
func (s *Store) Manage(name, action string, allowed []string, token string) error {
	if err := validName(name); err != nil {
		return err
	}
	switch action {
	case "rotate":
		if err := validProvisionToken(token); err != nil {
			return err
		}
	case "permissions":
		if err := validAllowed(allowed); err != nil {
			return err
		}
	case "revoke":
	default:
		return requestError(400, "invalid action")
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		p, err := loadPeer(tx, name)
		if err != nil {
			return err
		}
		if p == nil {
			return requestError(404, "unknown node")
		}
		switch action {
		case "rotate":
			hash := digest(token)
			tokens := tx.Bucket(tokensBucket)
			if owner := tokens.Get([]byte(hash)); owner != nil && string(owner) != name {
				return requestError(409, "token already assigned to a node")
			}
			if err := tokens.Delete([]byte(p.TokenHash)); err != nil {
				return err
			}
			if err := tokens.Put([]byte(hash), []byte(name)); err != nil {
				return err
			}
			p.TokenHash, p.Enabled = hash, true
		case "revoke":
			p.Enabled = false
		case "permissions":
			p.Allowed = append([]string{}, allowed...)
		}
		return putJSON(tx.Bucket(peersBucket), []byte(name), p)
	})
}

func (s *Store) now() float64 {
	t := time.Now()
	if s.Now != nil {
		t = s.Now()
	}
	return float64(t.Unix()) + float64(t.Nanosecond())/1e9
}

func loadRecord(tx *bolt.Tx, id string) (*record, error) {
	encoded := tx.Bucket(messagesBucket).Get([]byte(id))
	if encoded == nil {
		return nil, nil
	}
	var r record
	if err := json.Unmarshal(encoded, &r); err != nil {
		return nil, fmt.Errorf("decode message: %w", err)
	}
	return &r, nil
}

func saveRecord(tx *bolt.Tx, r *record) error {
	return putJSON(tx.Bucket(messagesBucket), []byte(r.Message.ID), r)
}

func public(r *record, now float64, includeReceipt bool) Message {
	m := r.Message
	m.AgentAwakened = "unverified"
	m.Receipt, m.LeaseUntil = "", 0
	switch {
	case m.AckedAt != nil:
		m.State = "acknowledged"
	case m.ExpiresAt <= now:
		m.State = "expired"
	case r.LeaseUntil > now:
		m.State = "leased"
	default:
		m.State = "queued"
	}
	if includeReceipt {
		m.Receipt, m.LeaseUntil = r.Receipt, r.LeaseUntil
	}
	return m
}

func validateSend(data SendRequest, replyTo string) error {
	if !utf8.ValidString(data.Body) {
		return requestError(400, "body must be valid UTF-8")
	}
	if strings.TrimSpace(data.Body) == "" || len(data.Body) > MaxBody {
		return requestError(400, "body must be nonempty UTF-8 text, at most 64 KiB")
	}
	if !idPattern.MatchString(data.ClientID) {
		return requestError(400, "client_id is required (1-128 ASCII identifier characters)")
	}
	if data.TTL < 1 || data.TTL > MaxTTL {
		return requestError(400, "ttl must be between 1 and 2592000")
	}
	if data.Kind != "" && !namePattern.MatchString(data.Kind) {
		return requestError(400, "kind must be 1-64 identifier characters")
	}
	if data.Conv != "" && !idPattern.MatchString(data.Conv) {
		return requestError(400, "conv must be 1-128 identifier characters")
	}
	if data.Hop < 0 || data.Hop > 100 {
		return requestError(400, "hop must be between 0 and 100")
	}
	if replyTo == "" {
		return validName(data.To)
	}
	if data.To != "" {
		return requestError(400, "reply recipient is derived from the parent message")
	}
	if !idPattern.MatchString(replyTo) {
		return requestError(400, "invalid message id")
	}
	return nil
}

// ValidateSend checks message shape before a client durably enqueues it. It
// performs no authentication, recipient lookup, or permissions check; Send
// repeats these shape checks and enforces authorization within its transaction.
func ValidateSend(data SendRequest, replyTo string) error {
	return validateSend(data, replyTo)
}

func fingerprint(data SendRequest, replyTo string) (string, error) {
	encoded, err := json.Marshal(struct {
		To      string `json:"to"`
		Body    string `json:"body"`
		TTL     int    `json:"ttl"`
		ReplyTo string `json:"reply_to"`
	}{data.To, data.Body, data.TTL, replyTo})
	if err != nil {
		return "", err
	}
	return digest(string(encoded)), nil
}

// Send authenticates inside the same write transaction that enforces ACLs,
// checks sender-scoped idempotency, and persists the new message and indexes.
func (s *Store) Send(token string, data SendRequest, replyTo string) (Message, error) {
	var out Message
	created := false
	err := s.db.Update(func(tx *bolt.Tx) error {
		actor, err := authenticate(tx, token)
		if err != nil {
			return err
		}
		out, created, err = s.sendTx(tx, actor.Name, data, replyTo)
		return err
	})
	if err != nil {
		return Message{}, err
	}
	if created {
		out.Created = true
		s.signal()
	}
	return out, nil
}

// SendAs behaves like Send for an already-authenticated peer, used by the MCP
// adapter whose callers hold OAuth access tokens rather than hub tokens.
func (s *Store) SendAs(name string, data SendRequest, replyTo string) (Message, error) {
	var out Message
	created := false
	err := s.db.Update(func(tx *bolt.Tx) error {
		actor, err := activePeer(tx, name)
		if err != nil {
			return err
		}
		out, created, err = s.sendTx(tx, actor.Name, data, replyTo)
		return err
	})
	if err != nil {
		return Message{}, err
	}
	if created {
		out.Created = true
		s.signal()
	}
	return out, nil
}

// activePeer loads a peer that must exist and be enabled.
func activePeer(tx *bolt.Tx, name string) (*peer, error) {
	p, err := loadPeer(tx, name)
	if err != nil {
		return nil, err
	}
	if p == nil || !p.Enabled {
		return nil, requestError(403, "node is disabled or unknown")
	}
	return p, nil
}

func (s *Store) sendTx(tx *bolt.Tx, sender string, data SendRequest, replyTo string) (Message, bool, error) {
	var out Message
	created := false
	err := func() error {
		if err := validateSend(data, replyTo); err != nil {
			return err
		}
		var parent *record
		recipient := data.To
		if replyTo != "" {
			var err error
			parent, err = loadRecord(tx, replyTo)
			if err != nil {
				return err
			}
			if parent == nil || parent.Message.Recipient != sender {
				return requestError(404, "reply target not found in your inbox")
			}
			recipient = parent.Message.Sender
		}
		target, err := loadPeer(tx, recipient)
		if err != nil {
			return err
		}
		if target == nil || !target.Enabled {
			return requestError(403, "node is disabled or unknown")
		}
		allowed := false
		actor, err := loadPeer(tx, sender)
		if err != nil {
			return err
		}
		for _, name := range actor.Allowed {
			if name == "*" || name == recipient {
				allowed = true
				break
			}
		}
		if !allowed {
			return requestError(403, "sending to this node is not allowed")
		}
		fp, err := fingerprint(data, replyTo)
		if err != nil {
			return err
		}
		key := []byte(sender + "\x00" + data.ClientID)
		dedupe := tx.Bucket(dedupeBucket)
		now := s.now() // Capture after acquiring the write lock, never before it.
		if id := dedupe.Get(key); id != nil {
			old, err := loadRecord(tx, string(id))
			if err != nil {
				return err
			}
			if old == nil {
				return errors.New("message idempotency index is inconsistent")
			}
			if old.Fingerprint != fp {
				return requestError(409, "client_id already used for a different message")
			}
			out = public(old, now, false)
			return nil
		}
		id, err := messageID()
		if err != nil {
			return err
		}
		if tx.Bucket(messagesBucket).Get([]byte(id)) != nil {
			return errors.New("random message id collision; retry the request")
		}
		seq, err := tx.Bucket(messagesBucket).NextSequence()
		if err != nil {
			return err
		}
		r := record{Message: Message{
			ID: id, Sender: sender, Recipient: recipient, ClientID: data.ClientID,
			ThreadID: id, Body: data.Body, CreatedAt: now, ExpiresAt: now + float64(data.TTL),
			Kind: data.Kind, Conv: data.Conv, Hop: data.Hop,
		}, Fingerprint: fp, Sequence: seq}
		if parent != nil {
			r.Message.ThreadID = parent.Message.ThreadID
			r.Message.ReplyTo = &replyTo
		}
		if err := saveRecord(tx, &r); err != nil {
			return err
		}
		if s.Lifecycle && data.Kind == "request" {
			q := Request{ID: id, State: RequestReceived, Seq: 1, Deadline: r.Message.ExpiresAt, UpdatedAt: now}
			if err := saveRequest(tx, &q); err != nil {
				return err
			}
		}
		if err := dedupe.Put(key, []byte(id)); err != nil {
			return err
		}
		inbox, err := tx.Bucket(inboxesBucket).CreateBucketIfNotExists([]byte(recipient))
		if err != nil {
			return err
		}
		var order [8]byte
		binary.BigEndian.PutUint64(order[:], seq)
		if err := inbox.Put(order[:], []byte(id)); err != nil {
			return err
		}
		created = true
		out = public(&r, now, false)
		return nil
	}()
	return out, created, err
}

// signal wakes every WaitInbox long-poll so it can re-scan its inbox.
func (s *Store) signal() {
	s.notifyMu.Lock()
	close(s.notify)
	s.notify = make(chan struct{})
	s.notifyMu.Unlock()
}

// PeerName resolves a bearer token to its peer name.
func (s *Store) PeerName(token string) (string, error) {
	var name string
	err := s.db.View(func(tx *bolt.Tx) error {
		p, err := authenticate(tx, token)
		if err != nil {
			return err
		}
		name = p.Name
		return nil
	})
	return name, err
}

// WaitInbox returns up to 100 unacknowledged, unexpired messages with an
// inbox sequence greater than after, along with the highest sequence scanned
// (the cursor for the next call). When nothing is available it blocks until
// a new message is committed or ctx expires; on timeout it returns an empty
// slice with the cursor unchanged, so reconnecting with the cursor never
// misses messages delivered while disconnected.
func (s *Store) WaitInbox(ctx context.Context, token string, after uint64) ([]Message, uint64, error) {
	for {
		msgs, cursor, err := s.scanInbox(token, after)
		if err != nil {
			return nil, after, err
		}
		if len(msgs) > 0 || cursor != after {
			return msgs, cursor, nil
		}
		s.notifyMu.Lock()
		ch := s.notify
		s.notifyMu.Unlock()
		select {
		case <-ch:
		case <-ctx.Done():
			return []Message{}, after, nil
		}
	}
}

func (s *Store) scanInbox(token string, after uint64) ([]Message, uint64, error) {
	msgs := []Message{}
	cursor := after
	err := s.db.View(func(tx *bolt.Tx) error {
		actor, err := authenticate(tx, token)
		if err != nil {
			return err
		}
		inbox := tx.Bucket(inboxesBucket).Bucket([]byte(actor.Name))
		if inbox == nil {
			return nil
		}
		now := s.now()
		var start [8]byte
		binary.BigEndian.PutUint64(start[:], after+1)
		c := inbox.Cursor()
		for key, id := c.Seek(start[:]); key != nil; key, id = c.Next() {
			if len(msgs) >= 100 {
				break
			}
			r, err := loadRecord(tx, string(id))
			if err != nil {
				return err
			}
			if r == nil || r.Message.Recipient != actor.Name {
				return errors.New("message inbox index is inconsistent")
			}
			seq := binary.BigEndian.Uint64(key)
			if r.Message.AckedAt == nil && r.Message.ExpiresAt > now {
				msgs = append(msgs, public(r, now, false))
			}
			cursor = seq
		}
		return nil
	})
	if err != nil {
		return nil, after, err
	}
	return msgs, cursor, nil
}

// Claim leases eligible messages in enqueue order. Concurrent claims cannot
// receive the same active lease. A later claim after expiry changes the receipt.
func (s *Store) Claim(token string, limit, lease int) ([]Message, error) {
	out := make([]Message, 0)
	err := s.db.Update(func(tx *bolt.Tx) error {
		actor, err := authenticate(tx, token)
		if err != nil {
			return err
		}
		if limit < 1 || limit > 100 {
			return requestError(400, "limit must be between 1 and 100")
		}
		if lease < 1 || lease > 3600 {
			return requestError(400, "lease must be between 1 and 3600")
		}
		now := s.now()
		inbox := tx.Bucket(inboxesBucket).Bucket([]byte(actor.Name))
		if inbox == nil {
			return nil
		}
		cursor := inbox.Cursor()
		for key, id := cursor.First(); key != nil && len(out) < limit; key, id = cursor.Next() {
			r, err := loadRecord(tx, string(id))
			if err != nil {
				return err
			}
			if r == nil || r.Message.Recipient != actor.Name {
				return errors.New("message inbox index is inconsistent")
			}
			if r.Message.AckedAt != nil || r.Message.ExpiresAt <= now || r.LeaseUntil > now {
				continue
			}
			r.Receipt, err = randomString(24)
			if err != nil {
				return err
			}
			r.LeaseUntil = now + float64(lease)
			r.Message.Attempts++
			if err := saveRecord(tx, r); err != nil {
				return err
			}
			out = append(out, public(r, now, true))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Ack confirms receipt by the consumer, not execution or awakening of an agent.
// Repeating the accepted receipt is idempotent even after its former lease ends.
func (s *Store) Ack(token, id, receipt string) (Message, error) {
	var out Message
	err := s.db.Update(func(tx *bolt.Tx) error {
		actor, err := authenticate(tx, token)
		if err != nil {
			return err
		}
		if !receiptPattern.MatchString(receipt) {
			return requestError(400, "receipt is required")
		}
		if !idPattern.MatchString(id) {
			return requestError(400, "invalid message id")
		}
		r, err := loadRecord(tx, id)
		if err != nil {
			return err
		}
		if r == nil || r.Message.Recipient != actor.Name {
			return requestError(404, "message not found")
		}
		if subtle.ConstantTimeCompare([]byte(r.Receipt), []byte(receipt)) != 1 {
			return requestError(409, "stale or invalid receipt")
		}
		now := s.now()
		if r.Message.AckedAt == nil {
			if r.LeaseUntil <= now || r.Message.ExpiresAt <= now {
				return requestError(409, "delivery lease or message expired; claim again")
			}
			r.Message.AckedAt = &now
			if err := saveRecord(tx, r); err != nil {
				return err
			}
		}
		out = public(r, now, false)
		return nil
	})
	if err != nil {
		return Message{}, err
	}
	return out, nil
}

// Get permits only the authenticated sender or recipient to inspect a message.
func (s *Store) Get(token, id string) (Message, error) {
	var out Message
	err := s.db.View(func(tx *bolt.Tx) error {
		actor, err := authenticate(tx, token)
		if err != nil {
			return err
		}
		out, err = getTx(tx, s.now(), actor.Name, id)
		return err
	})
	if err != nil {
		return Message{}, err
	}
	return out, nil
}

// GetAs behaves like Get for an already-authenticated peer (the MCP adapter).
func (s *Store) GetAs(name, id string) (Message, error) {
	var out Message
	err := s.db.View(func(tx *bolt.Tx) error {
		actor, err := activePeer(tx, name)
		if err != nil {
			return err
		}
		out, err = getTx(tx, s.now(), actor.Name, id)
		return err
	})
	if err != nil {
		return Message{}, err
	}
	return out, nil
}

func getTx(tx *bolt.Tx, now float64, name, id string) (Message, error) {
	if !idPattern.MatchString(id) {
		return Message{}, requestError(400, "invalid message id")
	}
	r, err := loadRecord(tx, id)
	if err != nil {
		return Message{}, err
	}
	if r == nil || (r.Message.Sender != name && r.Message.Recipient != name) {
		return Message{}, requestError(404, "message not found")
	}
	return public(r, now, false), nil
}

// PeekInboxAs returns up to limit unexpired messages in the peer's inbox,
// newest first, without leasing or acknowledging them. With unackedOnly,
// acknowledged messages are skipped; with conv non-empty, only messages of
// that conversation are returned. Used by the MCP read_messages tool.
func (s *Store) PeekInboxAs(name string, limit int, conv string, unackedOnly bool) ([]Message, error) {
	out := []Message{}
	err := s.db.View(func(tx *bolt.Tx) error {
		if _, err := activePeer(tx, name); err != nil {
			return err
		}
		inbox := tx.Bucket(inboxesBucket).Bucket([]byte(name))
		if inbox == nil {
			return nil
		}
		now := s.now()
		c := inbox.Cursor()
		for key, id := c.Last(); key != nil && len(out) < limit; key, id = c.Prev() {
			r, err := loadRecord(tx, string(id))
			if err != nil {
				return err
			}
			if r == nil || r.Message.Recipient != name {
				return errors.New("message inbox index is inconsistent")
			}
			if r.Message.ExpiresAt <= now || (unackedOnly && r.Message.AckedAt != nil) {
				continue
			}
			if conv != "" && r.Message.Conv != conv && r.Message.ThreadID != conv {
				continue
			}
			out = append(out, public(r, now, false))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
