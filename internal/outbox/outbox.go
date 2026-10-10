// Package outbox saves pending submissions before any network request.
// It never stores bearer tokens and never executes message bodies.
package outbox

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	bolt "go.etcd.io/bbolt"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

type Entry struct {
	Key       string          `json:"key"`
	Endpoint  string          `json:"endpoint"`
	TokenHash string          `json:"token_hash"`
	Route     string          `json:"route"`
	Body      json.RawMessage `json:"body"`
}
type Box struct{ db *bolt.DB }

func New(path string) (*Box, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("outbox directory must be a real private directory")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("outbox directory must have mode 0700")
	}
	if info, e := os.Lstat(path); e == nil && info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("outbox must not be a symlink")
	}
	db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, err
	}
	if err = os.Chmod(path, 0600); err != nil {
		db.Close()
		return nil, err
	}
	if err = db.Update(func(tx *bolt.Tx) error { _, e := tx.CreateBucketIfNotExists([]byte("pending")); return e }); err != nil {
		db.Close()
		return nil, err
	}
	return &Box{db: db}, nil
}
func (b *Box) Close() error { return b.db.Close() }
func hash(s string) string  { x := sha256.Sum256([]byte(s)); return hex.EncodeToString(x[:]) }
func (b *Box) Enqueue(endpoint, token, route, clientID string, body any) (Entry, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return Entry{}, err
	}
	e := Entry{Key: hash(endpoint + "\x00" + hash(token) + "\x00" + clientID), Endpoint: endpoint, TokenHash: hash(token), Route: route, Body: raw}
	data, _ := json.Marshal(e)
	err = b.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("pending"))
		if old := bucket.Get([]byte(e.Key)); old != nil && string(old) != string(data) {
			return errors.New("pending client_id has different request")
		}
		return bucket.Put([]byte(e.Key), data)
	})
	return e, err
}
func (b *Box) Pending(endpoint, token string) ([]Entry, error) {
	out := []Entry{}
	err := b.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("pending")).ForEach(func(_, v []byte) error {
			var e Entry
			if err := json.Unmarshal(v, &e); err != nil {
				return err
			}
			if e.Endpoint == endpoint && e.TokenHash == hash(token) {
				out = append(out, e)
			}
			return nil
		})
	})
	return out, err
}
func (b *Box) Complete(key string) error {
	return b.db.Update(func(tx *bolt.Tx) error { return tx.Bucket([]byte("pending")).Delete([]byte(key)) })
}
