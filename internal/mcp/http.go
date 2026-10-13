// HTTP transport for the MCP endpoint, mirroring dot-bridge's post_mcp:
// Bearer auth via OAuth access tokens, per-IP rate limit, Origin check,
// bounded bodies, no batching, Mcp-Method header consistency.
package mcp

import (
	"encoding/json"
	"io"
	"net/http"
	"relaynote/internal/oauth"
	"strings"
)

// Handler serves POST /mcp.
type Handler struct{ Server *Server }

func writeJSON(w http.ResponseWriter, status int, obj any, extra map[string]string) {
	body, err := json.Marshal(obj)
	if err != nil {
		status, body = 500, nil
	}
	h := w.Header()
	if obj != nil {
		h.Set("Content-Type", "application/json; charset=utf-8")
	}
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	for k, v := range extra {
		h.Set(k, v)
	}
	w.WriteHeader(status)
	if len(body) > 0 {
		_, _ = w.Write(body)
	}
}

// ServeHTTP handles /mcp; other paths get 404.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/mcp" {
		writeJSON(w, 404, map[string]string{"error": "not_found"}, nil)
		return
	}
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]string{"error": "use POST"}, map[string]string{"Allow": "POST"})
		return
	}
	s := h.Server
	// Origin check (DNS-rebinding defense): absent, "null", or the issuer.
	if origin := r.Header.Get("Origin"); origin != "" && origin != "null" && origin != s.OAuth.Issuer() {
		writeJSON(w, 403, map[string]string{"error": "forbidden_origin"}, nil)
		return
	}
	ip := oauth.ClientIP(r, s.OAuth.TrustedProxies())
	if s.Limiter != nil && s.Limiter.Limited("mcp:"+ip, 120) {
		writeJSON(w, 429, map[string]string{"error": "slow_down"}, nil)
		return
	}
	tok := ""
	if auth := r.Header.Get("Authorization"); len(auth) >= 7 && strings.EqualFold(auth[:7], "bearer ") {
		tok = strings.TrimSpace(auth[7:])
	}
	ident := s.OAuth.VerifyAccess(tok)
	if ident == nil {
		extra := map[string]string{}
		if tok != "" {
			extra["WWW-Authenticate"] = s.OAuth.WWWAuthenticate("invalid_token", "token missing, expired or not for this resource", "")
		} else {
			extra["WWW-Authenticate"] = s.OAuth.WWWAuthenticate("", "", "")
		}
		_, _ = io.Copy(io.Discard, r.Body)
		writeJSON(w, 401, map[string]string{"error": "invalid_token"}, extra)
		return
	}
	if r.ContentLength < 0 {
		writeJSON(w, 411, map[string]string{"error": "length_required"}, nil)
		return
	}
	if r.ContentLength > oauth.MaxBody {
		writeJSON(w, 413, map[string]string{"error": "too_large"}, nil)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, oauth.MaxBody+1))
	if err != nil || len(raw) > oauth.MaxBody {
		writeJSON(w, 413, map[string]string{"error": "too_large"}, nil)
		return
	}
	var msg any
	if err := json.Unmarshal(raw, &msg); err != nil {
		writeJSON(w, 400, rpcErr(nil, -32700, "Parse error"), nil)
		return
	}
	if _, isList := msg.([]any); isList {
		writeJSON(w, 400, rpcErr(nil, -32600, "batch requests are not supported"), nil)
		return
	}
	obj, ok := msg.(map[string]any)
	if !ok {
		writeJSON(w, 400, rpcErr(nil, -32600, "Invalid Request"), nil)
		return
	}
	if hdr := r.Header.Get("Mcp-Method"); hdr != "" {
		if m, _ := obj["method"].(string); hdr != m {
			writeJSON(w, 400, rpcErr(obj["id"], -32600, "Mcp-Method header mismatch"), nil)
			return
		}
	}
	resp := s.Handle(obj, ident)
	if resp == nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(202)
		return
	}
	writeJSON(w, 200, resp, nil)
}
