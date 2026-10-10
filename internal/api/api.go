// Package api implements the shared v1 protocol without Agent execution hooks.
package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"relaynote/internal/store"
	"strings"
	"unicode/utf8"
)

const MaxRequest = 400000

var messagePath = regexp.MustCompile(`^/v1/messages/([0-9a-f-]{36})(?:/(reply|ack))?$`)

type Handler struct {
	Store *store.Store
	slots chan struct{}
}

func New(s *store.Store) *Handler { return &Handler{Store: s, slots: make(chan struct{}, 32)} }

func response(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func fail(w http.ResponseWriter, status int, message string) {
	response(w, status, map[string]string{"error": message})
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	default:
		fail(w, 503, "too many active requests")
		return
	}
	if r.Header.Get("Origin") != "" {
		fail(w, 403, "browser origins are unsupported")
		return
	}
	a := r.Header.Values("Authorization")
	if len(a) != 1 || !strings.HasPrefix(a[0], "Bearer ") {
		fail(w, 401, "Bearer authentication required")
		return
	}
	token := strings.TrimPrefix(a[0], "Bearer ")
	if r.URL.RawQuery != "" || r.URL.EscapedPath() != r.URL.Path {
		fail(w, 400, "query or escaped routes are unsupported")
		return
	}
	var raw map[string]json.RawMessage
	if r.Method == http.MethodPost {
		if strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0]) != "application/json" {
			fail(w, 415, "application/json required")
			return
		}
		if len(r.TransferEncoding) > 0 || r.ContentLength < 0 {
			fail(w, 400, "Content-Length required")
			return
		}
		reader := http.MaxBytesReader(w, r.Body, MaxRequest)
		data, e := io.ReadAll(reader)
		if e != nil {
			var max *http.MaxBytesError
			if errors.As(e, &max) {
				fail(w, 413, "request too large")
			} else {
				fail(w, 400, "invalid request body")
			}
			return
		}
		raw, e = strictObject(data)
		if e != nil {
			fail(w, 400, "invalid JSON object")
			return
		}
	}
	var result any
	var err error
	if r.Method == http.MethodPost && r.URL.Path == "/v1/messages" {
		var req store.SendRequest
		req, err = sendRequest(raw, false)
		if err == nil {
			result, err = h.Store.Send(token, req, "")
		}
	} else if r.Method == http.MethodPost && r.URL.Path == "/v1/inbox/claim" {
		var opts struct {
			Limit *int `json:"limit"`
			Lease *int `json:"lease"`
		}
		err = decode(raw, &opts, "limit", "lease")
		limit, lease := 10, 300
		if opts.Limit != nil {
			limit = *opts.Limit
		}
		if opts.Lease != nil {
			lease = *opts.Lease
		}
		if err == nil {
			var messages []store.Message
			messages, err = h.Store.Claim(token, limit, lease)
			result = map[string]any{"messages": messages}
		}
	} else {
		matches := messagePath.FindStringSubmatch(r.URL.Path)
		if matches == nil {
			fail(w, 404, "unknown route")
			return
		}
		id, action := matches[1], matches[2]
		switch {
		case r.Method == http.MethodGet && action == "":
			result, err = h.Store.Get(token, id)
		case r.Method == http.MethodPost && action == "reply":
			var req store.SendRequest
			req, err = sendRequest(raw, true)
			if err == nil {
				result, err = h.Store.Send(token, req, id)
			}
		case r.Method == http.MethodPost && action == "ack":
			var req struct {
				Receipt string `json:"receipt"`
			}
			err = decode(raw, &req, "receipt")
			if err == nil {
				result, err = h.Store.Ack(token, id, req.Receipt)
			}
		default:
			fail(w, 405, "method not supported")
			return
		}
	}
	if err != nil {
		var se *store.Error
		if errors.As(err, &se) {
			fail(w, se.Status, se.Message)
		} else {
			fail(w, 503, "operation unavailable; retry sends with same client_id")
		}
		return
	}
	response(w, 200, result)
}

func bad(message string) error { return &store.Error{Status: 400, Message: message} }
func decode(raw map[string]json.RawMessage, out any, keys ...string) error {
	allowed := map[string]bool{}
	for _, k := range keys {
		allowed[k] = true
	}
	for k, v := range raw {
		if !allowed[k] || bytes.Equal(v, []byte("null")) {
			return bad("unknown or null field")
		}
	}
	data, _ := json.Marshal(raw)
	if err := json.Unmarshal(data, out); err != nil {
		return bad("invalid field type")
	}
	return nil
}
func sendRequest(raw map[string]json.RawMessage, reply bool) (store.SendRequest, error) {
	var req store.SendRequest
	keys := []string{"body", "client_id", "ttl"}
	if !reply {
		keys = append(keys, "to")
	}
	if err := decode(raw, &req, keys...); err != nil {
		return req, err
	}
	if _, ok := raw["ttl"]; !ok {
		req.TTL = 604800
	}
	return req, nil
}

// Reject duplicate keys and invalid Unicode rather than silently normalizing
// invalid JSON strings into a different authenticated message.
func strictObject(data []byte) (map[string]json.RawMessage, error) {
	if !utf8.Valid(data) || !validEscapes(data) {
		return nil, bad("invalid Unicode")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	t, e := d.Token()
	if e != nil || t != json.Delim('{') {
		return nil, bad("object required")
	}
	out := map[string]json.RawMessage{}
	for d.More() {
		t, e = d.Token()
		if e != nil {
			return nil, e
		}
		key, ok := t.(string)
		if !ok {
			return nil, bad("key required")
		}
		if _, exists := out[key]; exists {
			return nil, bad("duplicate key")
		}
		var v json.RawMessage
		if e = d.Decode(&v); e != nil {
			return nil, e
		}
		out[key] = v
	}
	if _, e = d.Token(); e != nil {
		return nil, e
	}
	if _, e = d.Token(); e != io.EOF {
		return nil, bad("trailing JSON")
	}
	return out, nil
}
func hex4(b []byte) int {
	if len(b) < 4 {
		return -1
	}
	n := 0
	for _, c := range b[:4] {
		n *= 16
		switch {
		case c >= '0' && c <= '9':
			n += int(c - '0')
		case c >= 'a' && c <= 'f':
			n += int(c - 'a' + 10)
		case c >= 'A' && c <= 'F':
			n += int(c - 'A' + 10)
		default:
			return -1
		}
	}
	return n
}
func validEscapes(data []byte) bool {
	for i := 0; i < len(data); i++ {
		if data[i] != '\\' {
			continue
		}
		i++
		if i >= len(data) {
			return false
		}
		if data[i] != 'u' {
			continue
		}
		if i+4 >= len(data) {
			return false
		}
		n := hex4(data[i+1:])
		if n < 0 {
			return false
		}
		i += 4
		if n >= 0xDC00 && n <= 0xDFFF {
			return false
		}
		if n >= 0xD800 && n <= 0xDBFF {
			if i+6 >= len(data) || data[i+1] != '\\' || data[i+2] != 'u' {
				return false
			}
			low := hex4(data[i+3:])
			if low < 0xDC00 || low > 0xDFFF {
				return false
			}
			i += 6
		}
	}
	return true
}
