package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

type fixture struct {
	s       *Store
	path    string
	a, b, c string
	clock   atomic.Int64
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{path: filepath.Join(t.TempDir(), "private", "queue.db")}
	var err error
	f.s, err = New(f.path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.s.Close() })
	f.clock.Store(time.Date(2026, 10, 10, 8, 0, 0, 0, time.UTC).UnixNano())
	f.s.Now = func() time.Time { return time.Unix(0, f.clock.Load()) }
	for _, node := range []struct {
		name    string
		allowed []string
		dest    *string
	}{{"A", []string{"B"}, &f.a}, {"B", []string{"A"}, &f.b}, {"C", nil, &f.c}} {
		*node.dest, err = NewToken()
		if err != nil {
			t.Fatal(err)
		}
		if err := f.s.Provision(node.name, node.allowed, *node.dest); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func (f *fixture) advance(d time.Duration) { f.clock.Add(int64(d)) }

func (f *fixture) send(t *testing.T, key string, ttl int) Message {
	t.Helper()
	m, err := f.s.Send(f.a, SendRequest{To: "B", Body: "合成测试", ClientID: key, TTL: ttl}, "")
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func assertStatus(t *testing.T, want int, err error) {
	t.Helper()
	var requestErr *Error
	if !errors.As(err, &requestErr) || requestErr.Status != want {
		t.Fatalf("wanted status %d, got %v", want, err)
	}
}

func claimOne(t *testing.T, s *Store, token string, lease int) Message {
	t.Helper()
	messages, err := s.Claim(token, 10, lease)
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) != 1 {
		t.Fatalf("wanted one message, got %d", len(messages))
	}
	return messages[0]
}

func assertNoReceipt(t *testing.T, m Message) {
	t.Helper()
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if m.Receipt != "" || m.LeaseUntil != 0 || bytes.Contains(data, []byte(`"receipt"`)) || bytes.Contains(data, []byte(`"lease_until"`)) {
		t.Fatalf("public message leaked claim credentials: %s", data)
	}
}

func TestRoundtripReplyAndAckMeaning(t *testing.T) {
	f := newFixture(t)
	m := f.send(t, "first", DefaultTTL)
	if m.State != "queued" || m.ThreadID != m.ID || m.ReplyTo != nil || m.AckedAt != nil {
		t.Fatalf("unexpected new message: %+v", m)
	}
	assertNoReceipt(t, m)
	c := claimOne(t, f.s, f.b, 300)
	if c.ID != m.ID || c.State != "leased" || c.Attempts != 1 || !receiptPattern.MatchString(c.Receipt) {
		t.Fatalf("unexpected claim: %+v", c)
	}
	ack, err := f.s.Ack(f.b, m.ID, c.Receipt)
	if err != nil {
		t.Fatal(err)
	}
	if ack.State != "acknowledged" || ack.AgentAwakened != "unverified" || ack.AckedAt == nil {
		t.Fatalf("acknowledgment must not imply execution: %+v", ack)
	}
	assertNoReceipt(t, ack)
	f.advance(31 * 24 * time.Hour)
	again, err := f.s.Ack(f.b, m.ID, c.Receipt)
	if err != nil || !reflect.DeepEqual(ack, again) {
		t.Fatalf("ack retry changed: %v, %+v", err, again)
	}
	reply, err := f.s.Send(f.b, SendRequest{Body: "reply", ClientID: "reply", TTL: DefaultTTL}, m.ID)
	if err != nil {
		t.Fatal(err)
	}
	if reply.ThreadID != m.ThreadID || reply.ReplyTo == nil || *reply.ReplyTo != m.ID || reply.Recipient != "A" || reply.Sender != "B" {
		t.Fatalf("reply thread not preserved: %+v", reply)
	}
	if received := claimOne(t, f.s, f.a, 300); received.ID != reply.ID {
		t.Fatalf("wrong reply: %+v", received)
	}
}

func TestAuthenticationAndInboxIsolation(t *testing.T) {
	f := newFixture(t)
	m := f.send(t, "first", DefaultTTL)
	_, err := f.s.Send("bad", SendRequest{}, "")
	assertStatus(t, 401, err)
	_, err = f.s.Get(f.c, m.ID)
	assertStatus(t, 404, err)
	_, err = f.s.Send(f.c, SendRequest{Body: "x", ClientID: "reply", TTL: DefaultTTL}, m.ID)
	assertStatus(t, 404, err)
	_, err = f.s.Send(f.a, SendRequest{Body: "x", ClientID: "reply", TTL: DefaultTTL}, m.ID)
	assertStatus(t, 404, err)
	_, err = f.s.Send(f.c, SendRequest{To: "A", Body: "x", ClientID: "blocked", TTL: DefaultTTL}, "")
	assertStatus(t, 403, err)
	c := claimOne(t, f.s, f.b, 300)
	_, err = f.s.Ack(f.c, m.ID, c.Receipt)
	assertStatus(t, 404, err)
	_, err = f.s.Ack(f.a, m.ID, c.Receipt)
	assertStatus(t, 404, err)
	for _, token := range []string{f.a, f.b} {
		got, err := f.s.Get(token, m.ID)
		if err != nil {
			t.Fatal(err)
		}
		assertNoReceipt(t, got)
	}
	if empty, err := f.s.Claim(f.c, 10, 300); err != nil || empty == nil || len(empty) != 0 {
		t.Fatalf("empty inbox must be a nonnil slice: %v, %#v", err, empty)
	}
}

func TestSenderScopedIdempotencyAndAllFingerprintFields(t *testing.T) {
	f := newFixture(t)
	m := f.send(t, "key", DefaultTTL)
	if again := f.send(t, "key", DefaultTTL); again.ID != m.ID {
		t.Fatal("identical retry created a duplicate")
	}
	if err := f.s.Manage("A", "permissions", []string{"B", "C"}, ""); err != nil {
		t.Fatal(err)
	}
	for _, req := range []SendRequest{
		{To: "B", Body: "changed", ClientID: "key", TTL: DefaultTTL},
		{To: "C", Body: "合成测试", ClientID: "key", TTL: DefaultTTL},
		{To: "B", Body: "合成测试", ClientID: "key", TTL: 10},
	} {
		_, err := f.s.Send(f.a, req, "")
		assertStatus(t, 409, err)
	}
	req := SendRequest{Body: "reply", ClientID: "key", TTL: DefaultTTL}
	r, err := f.s.Send(f.b, req, m.ID)
	if err != nil {
		t.Fatal(err)
	}
	again, err := f.s.Send(f.b, req, m.ID)
	if err != nil || r.ID != again.ID {
		t.Fatalf("reply retry failed: %v", err)
	}
	second := f.send(t, "second", DefaultTTL)
	_, err = f.s.Send(f.b, req, second.ID)
	assertStatus(t, 409, err)
	_, err = f.s.Send(f.b, SendRequest{To: "A", Body: "reply", ClientID: "key", TTL: DefaultTTL}, "")
	assertStatus(t, 409, err)
	if r.ID == m.ID {
		t.Fatal("client IDs must be sender scoped")
	}
}

func TestConcurrentSendsAndClaims(t *testing.T) {
	f := newFixture(t)
	var wg sync.WaitGroup
	ids := make(chan string, 32)
	errs := make(chan error, 32)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m, err := f.s.Send(f.a, SendRequest{To: "B", Body: "合成测试", ClientID: "same", TTL: DefaultTTL}, "")
			if err != nil {
				errs <- err
				return
			}
			ids <- m.ID
		}()
	}
	wg.Wait()
	close(ids)
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	unique := make(map[string]bool)
	for id := range ids {
		unique[id] = true
	}
	if len(unique) != 1 {
		t.Fatalf("idempotency raced: %d unique IDs", len(unique))
	}
	for i := 0; i < 20; i++ {
		f.send(t, fmt.Sprint(i), DefaultTTL)
	}
	claimed := make(chan []Message, 8)
	errs = make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			messages, err := f.s.Claim(f.b, 3, 300)
			if err != nil {
				errs <- err
				return
			}
			claimed <- messages
		}()
	}
	wg.Wait()
	close(claimed)
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	unique = make(map[string]bool)
	count := 0
	for group := range claimed {
		for _, m := range group {
			count++
			unique[m.ID] = true
		}
	}
	if count != 21 || len(unique) != count {
		t.Fatalf("concurrent claims duplicated/lost messages: count=%d unique=%d", count, len(unique))
	}
}

func TestFIFOAndExpiredItems(t *testing.T) {
	f := newFixture(t)
	f.send(t, "expired", 1)
	first := f.send(t, "first", DefaultTTL)
	second := f.send(t, "second", DefaultTTL)
	f.advance(time.Second)
	claimed, err := f.s.Claim(f.b, 1, 300)
	if err != nil || len(claimed) != 1 || claimed[0].ID != first.ID {
		t.Fatalf("wrong first claim: %v %+v", err, claimed)
	}
	if next := claimOne(t, f.s, f.b, 300); next.ID != second.ID {
		t.Fatalf("FIFO not preserved: %+v", next)
	}
}

func TestReopenAndLeaseRedelivery(t *testing.T) {
	f := newFixture(t)
	m := f.send(t, "persist", DefaultTTL)
	first := claimOne(t, f.s, f.b, 1)
	if err := f.s.Close(); err != nil {
		t.Fatal(err)
	}
	var err error
	f.s, err = New(f.path)
	if err != nil {
		t.Fatal(err)
	}
	f.s.Now = func() time.Time { return time.Unix(0, f.clock.Load()) }
	f.advance(500 * time.Millisecond)
	if messages, err := f.s.Claim(f.b, 10, 300); err != nil || len(messages) != 0 {
		t.Fatalf("persisted active lease lost: %v %+v", err, messages)
	}
	f.advance(500 * time.Millisecond)
	second := claimOne(t, f.s, f.b, 300)
	if second.ID != m.ID || second.Attempts != 2 || second.Receipt == first.Receipt {
		t.Fatalf("incorrect redelivery: %+v", second)
	}
	_, err = f.s.Ack(f.b, m.ID, first.Receipt)
	assertStatus(t, 409, err)
	if _, err := f.s.Ack(f.b, m.ID, second.Receipt); err != nil {
		t.Fatal(err)
	}
	if again := f.send(t, "persist", DefaultTTL); again.ID != m.ID || again.State != "acknowledged" {
		t.Fatalf("persisted idempotency lost: %+v", again)
	}
}

func TestLeaseAndTTLExactBoundaries(t *testing.T) {
	t.Run("lease", func(t *testing.T) {
		f := newFixture(t)
		m := f.send(t, "lease", DefaultTTL)
		claim := claimOne(t, f.s, f.b, 1)
		f.advance(time.Second)
		_, err := f.s.Ack(f.b, m.ID, claim.Receipt)
		assertStatus(t, 409, err)
		got, err := f.s.Get(f.a, m.ID)
		if err != nil || got.State != "queued" {
			t.Fatalf("lease boundary must requeue: %v %+v", err, got)
		}
	})
	t.Run("ttl", func(t *testing.T) {
		f := newFixture(t)
		m := f.send(t, "ttl", 1)
		claim := claimOne(t, f.s, f.b, 300)
		f.advance(time.Second)
		_, err := f.s.Ack(f.b, m.ID, claim.Receipt)
		assertStatus(t, 409, err)
		got, err := f.s.Get(f.a, m.ID)
		if err != nil || got.State != "expired" {
			t.Fatalf("TTL must override active lease: %v %+v", err, got)
		}
		messages, err := f.s.Claim(f.b, 10, 300)
		if err != nil || len(messages) != 0 {
			t.Fatalf("expired message was redelivered: %v %+v", err, messages)
		}
		if retry := f.send(t, "ttl", 1); retry.ID != m.ID || retry.State != "expired" {
			t.Fatalf("idempotent retry revived expired message: %+v", retry)
		}
	})
}

func TestRotationRevocationAndCurrentPermissions(t *testing.T) {
	f := newFixture(t)
	m := f.send(t, "sent", DefaultTTL)
	newToken, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.s.Manage("A", "rotate", nil, newToken); err != nil {
		t.Fatal(err)
	}
	_, err = f.s.Get(f.a, m.ID)
	assertStatus(t, 401, err)
	_, err = f.s.Send(f.a, SendRequest{To: "B", Body: "x", ClientID: "old", TTL: DefaultTTL}, "")
	assertStatus(t, 401, err)
	f.a = newToken
	if _, err := f.s.Get(f.a, m.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.s.Manage("A", "permissions", nil, ""); err != nil {
		t.Fatal(err)
	}
	_, err = f.s.Send(f.a, SendRequest{To: "B", Body: "合成测试", ClientID: "sent", TTL: DefaultTTL}, "")
	assertStatus(t, 403, err)
	if err := f.s.Manage("A", "revoke", nil, ""); err != nil {
		t.Fatal(err)
	}
	_, err = f.s.Claim(f.a, 10, 300)
	assertStatus(t, 401, err)
	_, err = f.s.Get(f.a, m.ID)
	assertStatus(t, 401, err)
	if err := f.s.Manage("A", "rotate", nil, f.a); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.Get(f.a, m.ID); err != nil {
		t.Fatal("rotation should reenable peer:", err)
	}
	if err := f.s.Manage("B", "revoke", nil, ""); err != nil {
		t.Fatal(err)
	}
	if err := f.s.Manage("A", "permissions", []string{"*"}, ""); err != nil {
		t.Fatal(err)
	}
	_, err = f.s.Send(f.a, SendRequest{To: "B", Body: "x", ClientID: "disabled-target", TTL: DefaultTTL}, "")
	assertStatus(t, 403, err)
}

func TestProvisionManageValidationAndDuplicateTokens(t *testing.T) {
	f := newFixture(t)
	assertStatus(t, 409, f.s.Provision("A", []string{"B"}, f.a))
	assertStatus(t, 409, f.s.Provision("D", []string{"B"}, f.a))
	assertStatus(t, 409, f.s.Manage("A", "rotate", nil, f.b))
	assertStatus(t, 404, f.s.Manage("unknown", "revoke", nil, ""))
	assertStatus(t, 400, f.s.Manage("A", "invalid", nil, ""))
	assertStatus(t, 400, f.s.Provision("bad/name", nil, f.a))
	assertStatus(t, 400, f.s.Provision("new", []string{"bad name"}, f.a))
	assertStatus(t, 400, f.s.Provision("new", make([]string, 101), f.a))
	assertStatus(t, 400, f.s.Manage("A", "permissions", make([]string, 101), ""))
	assertStatus(t, 400, f.s.Provision("new", nil, "bad-token"))
	assertStatus(t, 400, f.s.Manage("A", "rotate", nil, ""))
	// A failed token collision must not revoke the original credential.
	f.send(t, "still-authorized", DefaultTTL)
}

func TestMessageAndClaimValidation(t *testing.T) {
	f := newFixture(t)
	for _, body := range []string{"", " \t\n", strings.Repeat("x", MaxBody+1), string([]byte{0xff}), strings.Repeat("中", 21846)} {
		_, err := f.s.Send(f.a, SendRequest{To: "B", Body: body, ClientID: "body", TTL: DefaultTTL}, "")
		assertStatus(t, 400, err)
	}
	for _, id := range []string{"", "含中文", "has space", "slash/", strings.Repeat("x", 129)} {
		_, err := f.s.Send(f.a, SendRequest{To: "B", Body: "x", ClientID: id, TTL: DefaultTTL}, "")
		assertStatus(t, 400, err)
	}
	for _, ttl := range []int{-1, 0, MaxTTL + 1} {
		_, err := f.s.Send(f.a, SendRequest{To: "B", Body: "x", ClientID: "ttl", TTL: ttl}, "")
		assertStatus(t, 400, err)
	}
	for _, limit := range []int{-1, 0, 101} {
		_, err := f.s.Claim(f.b, limit, 300)
		assertStatus(t, 400, err)
	}
	for _, lease := range []int{-1, 0, 3601} {
		_, err := f.s.Claim(f.b, 10, lease)
		assertStatus(t, 400, err)
	}
	for _, receipt := range []string{"", "中文", strings.Repeat("x", 31), strings.Repeat("x", 33)} {
		_, err := f.s.Ack(f.b, "unknown", receipt)
		assertStatus(t, 400, err)
	}
	for _, id := range []string{"", "中文", "a/b", strings.Repeat("x", 129)} {
		_, err := f.s.Get(f.a, id)
		assertStatus(t, 400, err)
	}
	m := f.send(t, "parent", DefaultTTL)
	_, err := f.s.Send(f.b, SendRequest{To: "A", Body: "x", ClientID: "reply-to", TTL: DefaultTTL}, m.ID)
	assertStatus(t, 400, err)
	_, err = f.s.Send(f.a, SendRequest{To: "B", Body: strings.Repeat("x", MaxBody), ClientID: "body-boundary", TTL: MaxTTL}, "")
	if err != nil {
		t.Fatalf("boundary values must be accepted: %v", err)
	}
}

func TestWaitingForWriteLockUsesFreshClockAndCredentials(t *testing.T) {
	t.Run("clock", func(t *testing.T) {
		f := newFixture(t)
		f.send(t, "expires-while-waiting", 1)
		tx, err := f.s.db.Begin(true)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		result := make(chan error, 1)
		started := make(chan struct{})
		go func() {
			close(started)
			messages, err := f.s.Claim(f.b, 10, 300)
			if err == nil && len(messages) != 0 {
				err = errors.New("expired message claimed after waiting for lock")
			}
			result <- err
		}()
		<-started
		f.advance(2 * time.Second)
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		if err := <-result; err != nil {
			t.Fatal(err)
		}
	})
	t.Run("revocation", func(t *testing.T) {
		f := newFixture(t)
		f.send(t, "revoke-while-waiting", DefaultTTL)
		tx, err := f.s.db.Begin(true)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		p, err := loadPeer(tx, "B")
		if err != nil {
			t.Fatal(err)
		}
		p.Enabled = false
		if err := putJSON(tx.Bucket(peersBucket), []byte("B"), p); err != nil {
			t.Fatal(err)
		}
		result := make(chan error, 1)
		go func() {
			_, err := f.s.Claim(f.b, 10, 300)
			result <- err
		}()
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		assertStatus(t, 401, <-result)
	})
}

func TestTokenHashesOnlyAndPublicJSON(t *testing.T) {
	f := newFixture(t)
	m := f.send(t, "json", DefaultTTL)
	if err := f.s.db.View(func(tx *bolt.Tx) error {
		for _, name := range [][]byte{peersBucket, tokensBucket} {
			if err := tx.Bucket(name).ForEach(func(k, v []byte) error {
				for _, token := range []string{f.a, f.b, f.c} {
					if bytes.Contains(k, []byte(token)) || bytes.Contains(v, []byte(token)) {
						return errors.New("plaintext token persisted")
					}
				}
				return nil
			}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	if len(fields) != 13 || string(fields["reply_to"]) != "null" || string(fields["acked_at"]) != "null" {
		t.Fatalf("public fields changed: %s", data)
	}
}

func TestClaimRollsBackEveryLeaseOnError(t *testing.T) {
	f := newFixture(t)
	first := f.send(t, "first", DefaultTTL)
	second := f.send(t, "second", DefaultTTL)
	if err := f.s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(messagesBucket).Put([]byte(second.ID), []byte("invalid synthetic record"))
	}); err != nil {
		t.Fatal(err)
	}
	if messages, err := f.s.Claim(f.b, 10, 300); err == nil || messages != nil {
		t.Fatalf("corrupt claim batch should fail atomically: %v %+v", err, messages)
	}
	got, err := f.s.Get(f.a, first.ID)
	if err != nil || got.State != "queued" || got.Attempts != 0 {
		t.Fatalf("partial lease committed despite failed batch: %v %+v", err, got)
	}
}

func TestAuthenticationVerifiesPeerHashInsideTransaction(t *testing.T) {
	f := newFixture(t)
	m := f.send(t, "auth", DefaultTTL)
	if err := f.s.db.Update(func(tx *bolt.Tx) error {
		// A corrupt token index must never let A authenticate as B.
		return tx.Bucket(tokensBucket).Put([]byte(digest(f.a)), []byte("B"))
	}); err != nil {
		t.Fatal(err)
	}
	_, err := f.s.Get(f.a, m.ID)
	assertStatus(t, 401, err)
	_, err = f.s.Claim(f.a, 10, 300)
	assertStatus(t, 401, err)
}

func TestPrivatePathsAndExclusiveOwnership(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "private", "queue.db")
	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if other, err := New(path); err == nil {
		_ = other.Close()
		t.Fatal("second database owner was admitted")
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("database must be 0600: %v", err)
		}
		public := filepath.Join(dir, "public")
		if err := os.Mkdir(public, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(public, 0755); err != nil {
			t.Fatal(err)
		}
		if other, err := New(filepath.Join(public, "queue.db")); err == nil {
			_ = other.Close()
			t.Fatal("public directory was accepted")
		}
	}
	link := filepath.Join(dir, "db-link")
	if err := os.Symlink(path, link); err == nil {
		if other, err := New(link); err == nil {
			_ = other.Close()
			t.Fatal("symlink database was accepted")
		}
		dirLink := filepath.Join(dir, "dir-link")
		if err := os.Symlink(filepath.Dir(path), dirLink); err != nil {
			t.Fatal(err)
		}
		if other, err := New(filepath.Join(dirLink, "other.db")); err == nil {
			_ = other.Close()
			t.Fatal("symlink state directory was accepted")
		}
	}
	if other, err := New(""); err == nil {
		_ = other.Close()
		t.Fatal("empty database path was accepted")
	}
}

func TestRejectUnknownSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "future.db")
	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(metadataBucket).Put([]byte("schema"), []byte("999"))
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if reopened, err := New(path); err == nil {
		_ = reopened.Close()
		t.Fatal("unknown schema accepted")
	}
}

func TestCrashPersistence(t *testing.T) {
	const helperEnv = "RELAYNOTE_STORE_CRASH_HELPER"
	type manifest struct {
		A, B    string
		Claimed Message
	}
	if os.Getenv(helperEnv) == "1" {
		s, err := New(os.Getenv("RELAYNOTE_STORE_CRASH_PATH"))
		if err != nil {
			t.Fatal(err)
		}
		// Do not defer Close: the parent kills this synthetic helper after the
		// committed send and lease have been reported through stdout.
		a, err := NewToken()
		if err != nil {
			t.Fatal(err)
		}
		b, err := NewToken()
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Provision("A", []string{"B"}, a); err != nil {
			t.Fatal(err)
		}
		if err := s.Provision("B", []string{"A"}, b); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Send(a, SendRequest{To: "B", Body: "synthetic crash test", ClientID: "crash", TTL: DefaultTTL}, ""); err != nil {
			t.Fatal(err)
		}
		claimed := claimOne(t, s, b, 1)
		if err := json.NewEncoder(os.Stdout).Encode(manifest{A: a, B: b, Claimed: claimed}); err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Hour)
		return
	}
	path := filepath.Join(t.TempDir(), "private", "crash.db")
	cmd := exec.Command(os.Args[0], "-test.run=^TestCrashPersistence$")
	cmd.Env = append(os.Environ(), helperEnv+"=1", "RELAYNOTE_STORE_CRASH_PATH="+path)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()
	var before manifest
	ready := make(chan error, 1)
	go func() { ready <- json.NewDecoder(stdout).Decode(&before) }()
	select {
	case err := <-ready:
		if err != nil {
			t.Fatalf("crash helper failed: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("crash helper did not reach committed state")
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	s, err := New(path)
	if err != nil {
		t.Fatalf("reopen after kill: %v; helper stderr: %s", err, stderr.String())
	}
	defer s.Close()
	s.Now = func() time.Time { return time.Unix(int64(before.Claimed.LeaseUntil)+1, 0) }
	again := claimOne(t, s, before.B, 300)
	if again.ID != before.Claimed.ID || again.Attempts != 2 || again.Receipt == before.Claimed.Receipt {
		t.Fatalf("committed state lost after kill: %+v", again)
	}
	_, err = s.Ack(before.B, again.ID, before.Claimed.Receipt)
	assertStatus(t, 409, err)
	if _, err := s.Ack(before.B, again.ID, again.Receipt); err != nil {
		t.Fatal(err)
	}
	retried, err := s.Send(before.A, SendRequest{To: "B", Body: "synthetic crash test", ClientID: "crash", TTL: DefaultTTL}, "")
	if err != nil || retried.ID != again.ID || retried.State != "acknowledged" {
		t.Fatalf("dedupe not durable after kill: %v %+v", err, retried)
	}
}
