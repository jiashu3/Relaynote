package outbox

import (
	"path/filepath"
	"testing"
)

func TestRecoveryAndConflict(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "outbox.db")
	b, e := New(path)
	if e != nil {
		t.Fatal(e)
	}
	entry, e := b.Enqueue("https://example.invalid", "synthetic-token", "/v1/messages", "id", map[string]string{"body": "synthetic"})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = b.Enqueue("https://example.invalid", "synthetic-token", "/v1/messages", "id", map[string]string{"body": "changed"}); e == nil {
		t.Fatal("expected conflict")
	}
	b.Close()
	b, e = New(path)
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close()
	pending, e := b.Pending("https://example.invalid", "synthetic-token")
	if e != nil || len(pending) != 1 || pending[0].Key != entry.Key {
		t.Fatal(pending, e)
	}
	other, _ := b.Pending("https://other.invalid", "synthetic-token")
	if len(other) != 0 {
		t.Fatal("cross endpoint replay")
	}
	other, _ = b.Pending("https://example.invalid", "other-token")
	if len(other) != 0 {
		t.Fatal("cross identity replay")
	}
	if e = b.Complete(entry.Key); e != nil {
		t.Fatal(e)
	}
	pending, _ = b.Pending("https://example.invalid", "synthetic-token")
	if len(pending) != 0 {
		t.Fatal("not cleared")
	}
}
