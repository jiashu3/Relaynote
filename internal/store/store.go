// Package store implements Relaynote's durable, transactional message queue.
// A successful Send or Ack has committed to disk before returning. Delivery is
// at least once: consumers must make their own side effects idempotent by ID.
package store

import (
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
	namePattern    = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,64}$`)
	idPattern      = regexp.MustCompile(`^[a-zA-Z0-9_.:-]{1,128}$`)
	tokenPattern   = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	receiptPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{32}$`)
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
	Body          string   `json:"body"`
	CreatedAt     float64  `json:"created_at"`
	ExpiresAt     float64  `json:"expires_at"`
	AckedAt       *float64 `json:"acked_at"`
	Attempts      int      `json:"attempts"`
	State         string   `json:"state"`
	AgentAwakened string   `json:"agent_awakened"`
	Receipt       string   `json:"receipt,omitempty"`
	LeaseUntil    float64  `json:"lease_until,omitempty"`
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
	s := &Store{db: db}
	err = db.Update(func(tx *bolt.Tx) error {
		meta, err := tx.CreateBucketIfNotExists(metadataBucket)
		if err != nil {
			return err
		}
		version := meta.Get([]byte("schema"))
		if version != nil && string(version) != "1" {
			return fmt.Errorf("unsupported database schema %q", version)
		}
		for _, name := range [][]byte{peersBucket, tokensBucket, messagesBucket, dedupeBucket, inboxesBucket} {
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
	err := s.db.Update(func(tx *bolt.Tx) error {
		actor, err := authenticate(tx, token)
		if err != nil {
			return err
		}
		if err := validateSend(data, replyTo); err != nil {
			return err
		}
		var parent *record
		recipient := data.To
		if replyTo != "" {
			parent, err = loadRecord(tx, replyTo)
			if err != nil {
				return err
			}
			if parent == nil || parent.Message.Recipient != actor.Name {
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
		key := []byte(actor.Name + "\x00" + data.ClientID)
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
			ID: id, Sender: actor.Name, Recipient: recipient, ClientID: data.ClientID,
			ThreadID: id, Body: data.Body, CreatedAt: now, ExpiresAt: now + float64(data.TTL),
		}, Fingerprint: fp, Sequence: seq}
		if parent != nil {
			r.Message.ThreadID = parent.Message.ThreadID
			r.Message.ReplyTo = &replyTo
		}
		if err := saveRecord(tx, &r); err != nil {
			return err
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
		out = public(&r, now, false)
		return nil
	})
	if err != nil {
		return Message{}, err
	}
	return out, nil
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
		if !idPattern.MatchString(id) {
			return requestError(400, "invalid message id")
		}
		r, err := loadRecord(tx, id)
		if err != nil {
			return err
		}
		if r == nil || (r.Message.Sender != actor.Name && r.Message.Recipient != actor.Name) {
			return requestError(404, "message not found")
		}
		out = public(r, s.now(), false)
		return nil
	})
	if err != nil {
		return Message{}, err
	}
	return out, nil
}
