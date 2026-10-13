package store

import (
	"encoding/json"
	"strings"
	"unicode/utf8"

	bolt "go.etcd.io/bbolt"
)

// Request lifecycle states for messages carrying kind="request". Tracking is
// opt-in via Store.Lifecycle and is independent from delivery acknowledgment:
// Ack never changes lifecycle state and lifecycle transitions never touch
// AckedAt.
const (
	RequestReceived = "received"
	RequestRunning  = "running"
	RequestFinal    = "final"
	RequestTimedOut = "timed_out"
	RequestLate     = "late"
)

// Request tracks the execution lifecycle of one request message. Seq starts at
// 1 and increments on every transition, never resetting. Deadline equals the
// message expiry; timeout is applied lazily on the next lifecycle access.
type Request struct {
	ID        string  `json:"id"`
	State     string  `json:"state"`
	Seq       uint64  `json:"seq"`
	Deadline  float64 `json:"deadline"`
	Result    string  `json:"result,omitempty"`
	UpdatedAt float64 `json:"updated_at"`
}

func loadRequest(tx *bolt.Tx, id string) (*Request, error) {
	data := tx.Bucket(requestsBucket).Get([]byte(id))
	if data == nil {
		return nil, nil
	}
	var q Request
	if err := json.Unmarshal(data, &q); err != nil {
		return nil, err
	}
	return &q, nil
}

func saveRequest(tx *bolt.Tx, q *Request) error {
	return putJSON(tx.Bucket(requestsBucket), []byte(q.ID), q)
}

// refreshRequest applies the lazy timeout transition. Once timed out a request
// can never return to running; a later completion is recorded as late.
func refreshRequest(tx *bolt.Tx, q *Request, now float64) error {
	if (q.State == RequestReceived || q.State == RequestRunning) && q.Deadline <= now {
		q.State = RequestTimedOut
		q.Seq++
		q.UpdatedAt = now
		return saveRequest(tx, q)
	}
	return nil
}

// requestFor authenticates, loads the tracked request, and applies a pending
// timeout. recipientOnly restricts access to the message recipient.
func (s *Store) requestFor(tx *bolt.Tx, token, id string, recipientOnly bool) (*Request, error) {
	if !s.Lifecycle {
		return nil, requestError(400, "request lifecycle is disabled")
	}
	actor, err := authenticate(tx, token)
	if err != nil {
		return nil, err
	}
	if !idPattern.MatchString(id) {
		return nil, requestError(400, "invalid message id")
	}
	r, err := loadRecord(tx, id)
	if err != nil {
		return nil, err
	}
	visible := r != nil && (r.Message.Recipient == actor.Name || (!recipientOnly && r.Message.Sender == actor.Name))
	if !visible {
		return nil, requestError(404, "message not found")
	}
	q, err := loadRequest(tx, id)
	if err != nil {
		return nil, err
	}
	if q == nil {
		return nil, requestError(404, "message is not a tracked request")
	}
	if err := refreshRequest(tx, q, s.now()); err != nil {
		return nil, err
	}
	return q, nil
}

// StartRequest moves a received request to running. Only the recipient may
// start a request, and a timed-out request is rejected rather than re-run.
func (s *Store) StartRequest(token, id string) (Request, error) {
	var out Request
	err := s.db.Update(func(tx *bolt.Tx) error {
		q, err := s.requestFor(tx, token, id, true)
		if err != nil {
			return err
		}
		if q.State != RequestReceived {
			return requestError(409, "request cannot start from state "+q.State)
		}
		q.State, q.Seq, q.UpdatedAt = RequestRunning, q.Seq+1, s.now()
		if err := saveRequest(tx, q); err != nil {
			return err
		}
		out = *q
		return nil
	})
	if err != nil {
		return Request{}, err
	}
	return out, nil
}

// CompleteRequest records the result of a running request as final. A result
// arriving after the deadline is still recorded but marked late, never final.
func (s *Store) CompleteRequest(token, id, result string) (Request, error) {
	if !utf8.ValidString(result) || strings.TrimSpace(result) == "" || len(result) > MaxBody {
		return Request{}, requestError(400, "result must be nonempty UTF-8 text, at most 64 KiB")
	}
	var out Request
	err := s.db.Update(func(tx *bolt.Tx) error {
		q, err := s.requestFor(tx, token, id, true)
		if err != nil {
			return err
		}
		var next string
		switch q.State {
		case RequestRunning:
			next = RequestFinal
		case RequestTimedOut:
			next = RequestLate
		default:
			return requestError(409, "request cannot complete from state "+q.State)
		}
		q.State, q.Result, q.Seq, q.UpdatedAt = next, result, q.Seq+1, s.now()
		if err := saveRequest(tx, q); err != nil {
			return err
		}
		out = *q
		return nil
	})
	if err != nil {
		return Request{}, err
	}
	return out, nil
}

// GetRequest reports the lifecycle of a tracked request to its sender or
// recipient, applying a pending timeout first.
func (s *Store) GetRequest(token, id string) (Request, error) {
	var out Request
	err := s.db.Update(func(tx *bolt.Tx) error {
		q, err := s.requestFor(tx, token, id, false)
		if err != nil {
			return err
		}
		out = *q
		return nil
	})
	if err != nil {
		return Request{}, err
	}
	return out, nil
}
