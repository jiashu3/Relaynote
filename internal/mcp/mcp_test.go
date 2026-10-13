package mcp

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"relaynote/internal/events"
	"relaynote/internal/oauth"
	"relaynote/internal/store"
	"strings"
	"testing"
	"time"
)

const (
	testSeed = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	testPW   = "test-password-not-a-secret"
)

type fixture struct {
	t     *testing.T
	store *store.Store
	oauth *oauth.Server
	srv   *httptest.Server
	now   float64
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	st, err := store.New(filepath.Join(dir, "hub.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	// peers: the MCP peer "dot" may talk to grok-bot and lighthouse.
	for _, p := range []struct {
		name    string
		allowed []string
	}{{"dot", []string{"grok-bot", "lighthouse"}}, {"grok-bot", []string{"dot"}}, {"lighthouse", []string{"dot"}}} {
		tok, _ := store.NewToken()
		if err := st.Provision(p.name, p.allowed, tok); err != nil {
			t.Fatal(err)
		}
	}
	authFile := filepath.Join(dir, "auth.json")
	rec, _ := oauth.HashPassword(testPW)
	data, _ := json.Marshal(map[string]any{"password": rec, "totp_seed": testSeed})
	if err := os.WriteFile(authFile, data, 0600); err != nil {
		t.Fatal(err)
	}
	f := &fixture{t: t, store: st, now: 1791900000.0}
	// Bind first so the issuer URL is known before the server starts.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	issuer := "http://" + ln.Addr().String()
	oa, err := oauth.New(st.DB(), oauth.Config{
		Issuer: issuer, Peer: "dot", AuthFile: authFile,
		RedirectExact: []string{"http://127.0.0.1:18812/oauth-cb"},
	})
	if err != nil {
		t.Fatal(err)
	}
	oa.Now = func() time.Time { return time.Unix(int64(f.now), 0) }
	f.oauth = oa
	oh := &oauth.Handler{Server: oa, Limiter: oa.NewLimiter()}
	mh := &Handler{Server: &Server{
		Store: st, OAuth: oa, Events: events.New(st.DB(), &events.SafeHTTP{AllowInsecure: true}),
		Version: "test", Limiter: oa.NewLimiter(),
	}}
	f.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/mcp" {
			mh.ServeHTTP(w, r)
			return
		}
		oh.ServeHTTP(w, r)
	}))
	_ = f.srv.Listener.Close()
	f.srv.Listener = ln
	f.srv.Start()
	t.Cleanup(f.srv.Close)
	return f
}

// token runs a full login + code exchange and returns an access token.
func (f *fixture) token(scope string) string {
	f.t.Helper()
	cid := f.register()
	verifier := strings.Repeat("v", 50)
	chalSum := sha256b64(verifier)
	q := url.Values{"response_type": {"code"}, "client_id": {cid},
		"redirect_uri": {"http://127.0.0.1:18812/oauth-cb"}, "code_challenge": {chalSum},
		"code_challenge_method": {"S256"}, "state": {"st"}, "resource": {f.srv.URL + "/mcp"},
		"scope": {scope}}
	resp, err := http.Get(f.srv.URL + "/oauth/authorize?" + q.Encode())
	if err != nil {
		f.t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	m := regexp.MustCompile(`name="rid" value="([^"]+)"`).FindStringSubmatch(string(body))
	if m == nil {
		f.t.Fatalf("no rid: %d %s", resp.StatusCode, body)
	}
	form := url.Values{"rid": {m[1]}, "password": {testPW}, "action": {"approve"},
		"totp": {oauth.TOTPAt(testSeed, int64(f.now)/30)}}
	resp2, err := noRedirect().PostForm(f.srv.URL+"/oauth/authorize", form)
	if err != nil {
		f.t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != 302 {
		f.t.Fatalf("login: %d", resp2.StatusCode)
	}
	u, _ := url.Parse(resp2.Header.Get("Location"))
	code := u.Query().Get("code")
	resp3, err := noRedirect().PostForm(f.srv.URL+"/oauth/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "client_id": {cid},
		"redirect_uri": {"http://127.0.0.1:18812/oauth-cb"}, "code_verifier": {verifier}})
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp3.Body.Close()
	var tok struct {
		Access string `json:"access_token"`
	}
	if err := json.NewDecoder(resp3.Body).Decode(&tok); err != nil || tok.Access == "" {
		f.t.Fatalf("token: %v", err)
	}
	return tok.Access
}

func (f *fixture) register() string {
	f.t.Helper()
	resp, err := http.Post(f.srv.URL+"/oauth/register", "application/json",
		strings.NewReader(`{"redirect_uris":["http://127.0.0.1:18812/oauth-cb"]}`))
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		ClientID string `json:"client_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		f.t.Fatal(err)
	}
	return out.ClientID
}

func sha256b64(s string) string {
	sum := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func noRedirect() *http.Client {
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}

// rpc posts one JSON-RPC message and returns status + decoded body.
func (f *fixture) rpc(token, method string, params any) (int, map[string]any) {
	f.t.Helper()
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	req, _ := http.NewRequest("POST", f.srv.URL+"/mcp", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Mcp-Method", method)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	raw, _ := io.ReadAll(resp.Body)
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &out); err != nil {
			f.t.Fatalf("bad JSON from %s: %s", method, raw)
		}
	}
	return resp.StatusCode, out
}

func (f *fixture) call(token, tool string, args map[string]any) (int, map[string]any) {
	return f.rpc(token, "tools/call", map[string]any{"name": tool, "arguments": args})
}

func resultErr(t *testing.T, out map[string]any) map[string]any {
	t.Helper()
	res, ok := out["result"].(map[string]any)
	if !ok {
		t.Fatalf("no result: %v", out)
	}
	if res["isError"] != true {
		t.Fatalf("not an error result: %v", res)
	}
	sc, ok := res["structuredContent"].(map[string]any)
	if !ok {
		t.Fatalf("no structuredContent: %v", res)
	}
	return sc
}

func TestAuthAndTransport(t *testing.T) {
	f := newFixture(t)
	// no token -> 401 with resource_metadata challenge
	st, out := f.rpc("", "tools/list", nil)
	if st != 401 || out["error"] != "invalid_token" {
		t.Fatalf("%d %v", st, out)
	}
	// forged token -> 401
	st, _ = f.rpc("rna_forged", "tools/list", nil)
	if st != 401 {
		t.Fatalf("%d", st)
	}
	tok := f.token("messages:read messages:send events:subscribe")
	// GET -> 405
	resp, err := http.Get(f.srv.URL + "/mcp")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 405 || resp.Header.Get("Allow") != "POST" {
		t.Fatalf("%d", resp.StatusCode)
	}
	// bad JSON -> -32700; batch -> -32600; header mismatch -> -32600
	for _, tc := range []struct {
		body, hdr string
		code      float64
	}{
		{"{bad", "", -32700},
		{`[]`, "", -32600},
		{`{"jsonrpc":"2.0","id":1,"method":"ping"}`, "other", -32600},
	} {
		req, _ := http.NewRequest("POST", f.srv.URL+"/mcp", strings.NewReader(tc.body))
		req.Header.Set("Authorization", "Bearer "+tok)
		if tc.hdr != "" {
			req.Header.Set("Mcp-Method", tc.hdr)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var out map[string]any
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		_ = json.Unmarshal(raw, &out)
		if resp.StatusCode != 400 || out["error"].(map[string]any)["code"] != tc.code {
			t.Fatalf("%q: %d %v", tc.body, resp.StatusCode, out)
		}
	}
	// notification -> 202 empty
	req, _ := http.NewRequest("POST", f.srv.URL+"/mcp",
		strings.NewReader(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 202 {
		t.Fatalf("notification: %d", resp.StatusCode)
	}
	// Origin check
	req, _ = http.NewRequest("POST", f.srv.URL+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Origin", "https://evil.example")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("origin: %d", resp.StatusCode)
	}
}

func TestMethodsAndScopes(t *testing.T) {
	f := newFixture(t)
	tok := f.token("messages:read messages:send events:subscribe")
	st, out := f.rpc(tok, "initialize", map[string]any{"protocolVersion": "2025-06-18"})
	res := out["result"].(map[string]any)
	if st != 200 || res["protocolVersion"] != "2025-06-18" {
		t.Fatalf("%d %v", st, out)
	}
	st, out = f.rpc(tok, "initialize", map[string]any{"protocolVersion": "bogus"})
	if out["result"].(map[string]any)["protocolVersion"] != SupportedVersions[0] {
		t.Fatalf("%v", out)
	}
	st, out = f.rpc(tok, "tools/list", nil)
	tools := out["result"].(map[string]any)["tools"].([]any)
	names := []string{}
	for _, tool := range tools {
		names = append(names, tool.(map[string]any)["name"].(string))
	}
	if fmt.Sprint(names) != "[read_messages send_message status]" {
		t.Fatalf("%v", names)
	}
	_, out = f.rpc(tok, "nope/nope", nil)
	if out["error"].(map[string]any)["code"] != -32601.0 {
		t.Fatalf("%v", out)
	}
	_, out = f.call(tok, "nope", nil)
	if out["error"].(map[string]any)["code"] != -32602.0 {
		t.Fatalf("%v", out)
	}
	_, out = f.rpc(tok, "resources/list", nil)
	if v, ok := out["result"].(map[string]any)["resources"].([]any); !ok || len(v) != 0 {
		t.Fatalf("%v", out)
	}

	// a read-only token may not send
	f.adv(31) // fresh TOTP step for the second login
	roTok := f.token("messages:read")
	_, out = f.call(roTok, "send_message", map[string]any{"text": "x", "to": "grok-bot"})
	// insufficient scope renders as isError content with a www_authenticate hint
	scRes := out["result"].(map[string]any)
	if scRes["isError"] != true || !strings.Contains(jsonText(scRes["_meta"]), "insufficient_scope") {
		t.Fatalf("%v", scRes)
	}
	// events/subscribe needs events:subscribe
	_, out = f.rpc(roTok, "events/subscribe", map[string]any{"name": "message.created"})
	if out["error"].(map[string]any)["code"] != -32001.0 {
		t.Fatalf("%v", out)
	}
}

func (f *fixture) adv(sec float64) { f.now += sec }

func TestTools(t *testing.T) {
	f := newFixture(t)
	tok := f.token("messages:read messages:send events:subscribe")

	// argument validation, same codes as dot-bridge
	_, out := f.call(tok, "send_message", map[string]any{})
	if sc := resultErr(t, out); sc["error"] != "invalid_arguments" || sc["message"] != "text is required" {
		t.Fatalf("%v", sc)
	}
	_, out = f.call(tok, "send_message", map[string]any{"text": "hi", "bogus": 1})
	if sc := resultErr(t, out); sc["message"] != "unknown arguments: ['bogus']" {
		t.Fatalf("%v", sc)
	}
	_, out = f.call(tok, "send_message", map[string]any{"text": strings.Repeat("x", MaxText+1), "to": "grok-bot"})
	if sc := resultErr(t, out); sc["error"] != "text_too_long" {
		t.Fatalf("%v", sc)
	}
	_, out = f.call(tok, "read_messages", map[string]any{"limit": 99})
	if sc := resultErr(t, out); sc["message"] != "limit must be 1..10" {
		t.Fatalf("%v", sc)
	}
	// ACL: dot may not send to an unknown/disallowed peer
	_, out = f.call(tok, "send_message", map[string]any{"text": "hi", "to": "manus-cue"})
	if sc := resultErr(t, out); sc["error"] != "recipient_not_allowed" {
		t.Fatalf("%v", sc)
	}

	// send + idempotent replay
	_, out = f.call(tok, "send_message", map[string]any{"text": "golden 1", "to": "grok-bot",
		"idempotency_key": "k1", "conversation_id": "c-1"})
	res := out["result"].(map[string]any)
	sc := res["structuredContent"].(map[string]any)
	if sc["duplicate"] != false || sc["to"] != "grok-bot" {
		t.Fatalf("%v", sc)
	}
	mid := sc["message_id"].(string)
	_, out = f.call(tok, "send_message", map[string]any{"text": "golden 1", "to": "grok-bot",
		"idempotency_key": "k1", "conversation_id": "c-1"})
	sc = out["result"].(map[string]any)["structuredContent"].(map[string]any)
	if sc["duplicate"] != true || sc["message_id"] != mid {
		t.Fatalf("idempotent replay: %v", sc)
	}

	// grok-bot replies; dot reads its inbox via MCP
	grokTok := peerToken(t, f.store, "grok-bot")
	if _, err := f.store.Send(grokTok, store.SendRequest{
		To: "dot", Body: "hello dot", ClientID: "g1", TTL: 3600, Kind: "chat", Conv: "c-9"}, ""); err != nil {
		t.Fatal(err)
	}
	_, out = f.call(tok, "read_messages", map[string]any{})
	msgs := out["result"].(map[string]any)["structuredContent"].(map[string]any)["messages"].([]any)
	if len(msgs) != 1 {
		t.Fatalf("inbox: %v", msgs)
	}
	m := msgs[0].(map[string]any)
	if m["from"] != "grok-bot" || m["text"] != "hello dot" || m["kind"] != "chat" || m["conversation_id"] != "c-9" {
		t.Fatalf("%v", m)
	}
	// by id
	_, out = f.call(tok, "read_messages", map[string]any{"message_id": m["message_id"]})
	if n := len(out["result"].(map[string]any)["structuredContent"].(map[string]any)["messages"].([]any)); n != 1 {
		t.Fatalf("by id: %d", n)
	}
	// unknown id -> unknown_message
	_, out = f.call(tok, "read_messages", map[string]any{"message_id": "00000000-0000-4000-8000-000000000000"})
	if sc := resultErr(t, out); sc["error"] != "unknown_message" {
		t.Fatalf("%v", sc)
	}
	// reply via reply_to
	_, out = f.call(tok, "send_message", map[string]any{"text": "answer", "reply_to": m["message_id"].(string)})
	sc = out["result"].(map[string]any)["structuredContent"].(map[string]any)
	if sc["to"] != "grok-bot" || sc["duplicate"] != false {
		t.Fatalf("reply: %v", sc)
	}
	// reply to unknown message
	_, out = f.call(tok, "send_message", map[string]any{"text": "answer", "reply_to": "00000000-0000-4000-8000-000000000000"})
	if sc := resultErr(t, out); sc["error"] != "unknown_message" {
		t.Fatalf("%v", sc)
	}
	// status
	_, out = f.call(tok, "status", map[string]any{})
	sc = out["result"].(map[string]any)["structuredContent"].(map[string]any)
	if sc["peer"] != "dot" || sc["unacked_messages"] != 1.0 {
		t.Fatalf("%v", sc)
	}
}

func peerToken(t *testing.T, st *store.Store, name string) string {
	t.Helper()
	// Re-provision is impossible; use manage rotate to learn a token.
	tok, err := store.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Manage(name, "rotate", nil, tok); err != nil {
		t.Fatal(err)
	}
	return tok
}
