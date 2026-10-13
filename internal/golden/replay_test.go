// Package golden replays the dot-bridge golden scenario subset (OAuth error
// branches, MCP protocol methods, tool argument errors, login rate limiting)
// against Relaynote's P2 endpoints and compares status code + error code /
// JSON shape field-by-field, like team/gateway-src/golden/compare.py does.
// Volatile values (tokens, ids, codes, timestamps) are wildcards in the
// fixture; see testdata/README.md for intentional divergences.
package golden

import (
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
	"reflect"
	"regexp"
	"relaynote/internal/events"
	"relaynote/internal/mcp"
	"relaynote/internal/oauth"
	"relaynote/internal/store"
	"strings"
	"testing"
	"time"
)

const (
	seed     = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP" // golden fixture seed, not a secret
	password = "golden-password-not-a-secret"
	redirect = "http://127.0.0.1:18812/oauth-cb"
)

type step struct {
	Golden     int                 `json:"golden"`
	Req        string              `json:"req"`
	Status     int                 `json:"status"`
	Headers    map[string]any      `json:"headers,omitempty"`
	Body       any                 `json:"body"`
	HTMLErr    string              `json:"html_err,omitempty"`
	Mode       string              `json:"mode,omitempty"`
	ExactKeys  []string            `json:"exact_keys,omitempty"`
	IgnoreKeys []string            `json:"ignore_keys,omitempty"`
	Tools      map[string][]string `json:"tools,omitempty"`
}

type scenario struct {
	Steps []step `json:"steps"`
}

type replay struct {
	t      *testing.T
	base   string
	now    float64
	cid    string
	tokens map[string]any // last token response
}

var wildcard = regexp.MustCompile(`^\{[A-Z_]+\}$`)

func loadScenario(t *testing.T) scenario {
	t.Helper()
	data, err := os.ReadFile("testdata/scenario.json")
	if err != nil {
		t.Fatal(err)
	}
	var sc scenario
	if err := json.Unmarshal(data, &sc); err != nil {
		t.Fatal(err)
	}
	return sc
}

// substVars replaces {BASE} placeholders throughout a fixture step; {CID},
// {TOKEN}, {CODE} and {ANY} stay as whole-value wildcards for compareJSON.
func (r *replay) substVars(v any) any {
	switch w := v.(type) {
	case string:
		if wildcard.MatchString(w) {
			return w
		}
		return r.subst(w)
	case []any:
		for i := range w {
			w[i] = r.substVars(w[i])
		}
	case map[string]any:
		for k := range w {
			w[k] = r.substVars(w[k])
		}
	}
	return v
}

func (r *replay) substStep(s step) step {
	s.Req = r.subst(s.Req)
	for k, v := range s.Headers {
		s.Headers[k] = r.substVars(v)
	}
	s.Body = r.substVars(s.Body)
	return s
}

// --- comparison, mirroring compare.py's field-by-field check

func (r *replay) subst(s string) string {
	return strings.ReplaceAll(s, "{BASE}", r.base)
}

func compareJSON(path string, want, got any, ignore map[string]bool, exactKeys map[string]bool, shape bool) error {
	if w, ok := want.(string); ok && wildcard.MatchString(w) {
		switch g := got.(type) {
		case string:
			if g == "" {
				return fmt.Errorf("%s: want non-empty wildcard, got empty", path)
			}
			return nil
		case float64, bool:
			return nil
		default:
			return fmt.Errorf("%s: wildcard got %T", path, got)
		}
	}
	if shape {
		return compareShape(path, want, got, exactKeys)
	}
	switch w := want.(type) {
	case nil:
		if got != nil {
			return fmt.Errorf("%s: want null, got %v", path, got)
		}
	case string:
		g, ok := got.(string)
		if !ok {
			return fmt.Errorf("%s: want string, got %T", path, got)
		}
		// content[].text carries JSON-encoded structuredContent in both
		// implementations; compare it as JSON, not as formatting.
		var wj, gj any
		if json.Unmarshal([]byte(w), &wj) == nil && json.Unmarshal([]byte(g), &gj) == nil {
			return compareJSON(path, wj, gj, ignore, exactKeys, false)
		}
		if g != w {
			return fmt.Errorf("%s: want %q, got %q", path, w, g)
		}
	case float64:
		g, ok := got.(float64)
		if !ok || g != w {
			return fmt.Errorf("%s: want %v, got %v", path, w, got)
		}
	case bool:
		g, ok := got.(bool)
		if !ok || g != w {
			return fmt.Errorf("%s: want %v, got %v", path, w, got)
		}
	case []any:
		g, ok := got.([]any)
		if !ok || len(g) != len(w) {
			return fmt.Errorf("%s: want array len %d, got %v", path, len(w), got)
		}
		for i := range w {
			if err := compareJSON(fmt.Sprintf("%s[%d]", path, i), w[i], g[i], ignore, exactKeys, shape); err != nil {
				return err
			}
		}
	case map[string]any:
		g, ok := got.(map[string]any)
		if !ok {
			return fmt.Errorf("%s: want object, got %T", path, got)
		}
		for k := range w {
			if ignore[k] {
				continue
			}
			gv, exists := g[k]
			if !exists {
				return fmt.Errorf("%s.%s: missing", path, k)
			}
			if err := compareJSON(path+"."+k, w[k], gv, ignore, exactKeys, shape); err != nil {
				return err
			}
		}
		for k := range g {
			if ignore[k] {
				continue
			}
			if _, exists := w[k]; !exists {
				return fmt.Errorf("%s.%s: unexpected key (value %v)", path, k, g[k])
			}
		}
	default:
		return fmt.Errorf("%s: unhandled fixture type %T", path, want)
	}
	return nil
}

// compareShape compares JSON shape: identical key sets, equal-length arrays,
// same scalar types; scalar values are ignored unless the key is in exactKeys.
func compareShape(path string, want, got any, exactKeys map[string]bool) error {
	switch w := want.(type) {
	case map[string]any:
		g, ok := got.(map[string]any)
		if !ok {
			return fmt.Errorf("%s: want object, got %T", path, got)
		}
		if len(w) != len(g) {
			return fmt.Errorf("%s: key sets differ: %v vs %v", path, keys(w), keys(g))
		}
		for k, wv := range w {
			gv, ok := g[k]
			if !ok {
				return fmt.Errorf("%s.%s: missing", path, k)
			}
			if exactKeys[k] {
				if err := compareJSON(path+"."+k, wv, gv, nil, nil, false); err != nil {
					return err
				}
				continue
			}
			if err := compareShape(path+"."+k, wv, gv, exactKeys); err != nil {
				return err
			}
		}
	case []any:
		g, ok := got.([]any)
		if !ok || len(g) != len(w) {
			return fmt.Errorf("%s: want array len %d, got %v", path, len(w), got)
		}
		for i := range w {
			if err := compareShape(fmt.Sprintf("%s[%d]", path, i), w[i], g[i], exactKeys); err != nil {
				return err
			}
		}
	default:
		if reflect.TypeOf(want) != reflect.TypeOf(got) {
			return fmt.Errorf("%s: type %T vs %T", path, want, got)
		}
	}
	return nil
}

func keys(m map[string]any) []string {
	out := []string{}
	for k := range m {
		out = append(out, k)
	}
	return out
}

var (
	errRe  = regexp.MustCompile(`<p class="err">([^<]*)</p>`)
	pageRe = regexp.MustCompile(`</h2>\n?<p>([^<]*)</p>`)
)

func htmlErr(body string) string {
	if m := errRe.FindStringSubmatch(body); m != nil {
		return m[1]
	}
	if m := pageRe.FindStringSubmatch(body); m != nil {
		return m[1]
	}
	return ""
}

func (r *replay) check(s step, status int, header http.Header, body []byte) {
	r.t.Helper()
	s = r.substStep(s)
	label := fmt.Sprintf("golden[%d] %s", s.Golden, s.Req)
	if status != s.Status {
		r.t.Fatalf("%s: status %d, want %d (body %s)", label, status, s.Status, body)
	}
	for k, v := range s.Headers {
		got := header.Get(k)
		switch w := v.(type) {
		case string:
			if got != r.subst(w) {
				r.t.Fatalf("%s: header %s = %q, want %q", label, k, got, r.subst(w))
			}
		case map[string]any:
			if k == "Location" {
				r.checkLocation(label, got, w)
			} else if k == "Set-Cookie" {
				r.checkCookie(label, got, w)
			} else {
				r.t.Fatalf("%s: structured header %s not supported", label, k)
			}
		}
	}
	ignore := map[string]bool{}
	for _, k := range s.IgnoreKeys {
		ignore[k] = true
	}
	exact := map[string]bool{}
	for _, k := range s.ExactKeys {
		exact[k] = true
	}
	switch s.Mode {
	case "tools":
		var got map[string]any
		if err := json.Unmarshal(body, &got); err != nil {
			r.t.Fatalf("%s: bad JSON: %s", label, body)
		}
		r.checkTools(label, got, s.Tools)
	case "shape":
		var got any
		if err := json.Unmarshal(body, &got); err != nil {
			r.t.Fatalf("%s: bad JSON: %s", label, body)
		}
		if err := compareShape("body", s.Body, got, exact); err != nil {
			r.t.Fatalf("%s: %v", label, err)
		}
	default:
		if s.HTMLErr != "" {
			if got := htmlErr(string(body)); got != s.HTMLErr {
				r.t.Fatalf("%s: html err %q, want %q", label, got, s.HTMLErr)
			}
			return
		}
		if s.Body == nil {
			// HTML login pages without an expected error message compare
			// status + Content-Type only (page chrome is a documented
			// divergence); any other nil body must be empty.
			if ct, ok := s.Headers["Content-Type"].(string); ok && strings.HasPrefix(ct, "text/html") {
				return
			}
			if len(body) != 0 {
				r.t.Fatalf("%s: want empty body, got %s", label, body)
			}
			return
		}
		var got any
		if err := json.Unmarshal(body, &got); err != nil {
			r.t.Fatalf("%s: bad JSON: %s", label, body)
		}
		if err := compareJSON("body", s.Body, got, ignore, exact, false); err != nil {
			r.t.Fatalf("%s: %v", label, err)
		}
	}
}

func (r *replay) checkLocation(label, got string, want map[string]any) {
	u, err := url.Parse(got)
	if err != nil {
		r.t.Fatalf("%s: bad Location %q", label, got)
	}
	if u.Scheme+"://"+u.Host+u.Path != want["path"] {
		r.t.Fatalf("%s: Location path %q", label, got)
	}
	wantQ, _ := want["query"].(map[string]any)
	q := u.Query()
	for k, w := range wantQ {
		ws, _ := w.(string)
		ws = r.subst(ws)
		if wildcard.MatchString(ws) {
			if q.Get(k) == "" {
				r.t.Fatalf("%s: Location param %s empty", label, k)
			}
			continue
		}
		if q.Get(k) != ws {
			r.t.Fatalf("%s: Location param %s = %q, want %q", label, k, q.Get(k), ws)
		}
	}
	if len(q) != len(wantQ) {
		r.t.Fatalf("%s: Location query %v, want keys %v", label, q, keys(wantQ))
	}
}

func (r *replay) checkCookie(label, got string, want map[string]any) {
	parts := strings.Split(got, "; ")
	attrs := map[string]string{}
	flags := map[string]bool{}
	for _, p := range parts[1:] {
		if k, v, ok := strings.Cut(p, "="); ok {
			attrs[strings.ToLower(k)] = v
		} else {
			flags[strings.ToLower(p)] = true
		}
	}
	if attrs["path"] != want["path"] || attrs["max-age"] != want["max_age"] {
		r.t.Fatalf("%s: Set-Cookie %q", label, got)
	}
	if flags["httponly"] != want["http_only"] || attrs["samesite"] != want["same_site"] {
		r.t.Fatalf("%s: Set-Cookie %q", label, got)
	}
	if parts[0] == "" || !strings.Contains(parts[0], "=") {
		r.t.Fatalf("%s: Set-Cookie %q has no value", label, got)
	}
}

// checkTools verifies the two golden tools exist with the same OAuth scopes;
// tool descriptions and extra tools (status) are documented divergences.
func (r *replay) checkTools(label string, got map[string]any, want map[string][]string) {
	res, ok := got["result"].(map[string]any)
	if !ok {
		r.t.Fatalf("%s: no result", label)
	}
	tools, ok := res["tools"].([]any)
	if !ok {
		r.t.Fatalf("%s: no tools", label)
	}
	byName := map[string]map[string]any{}
	for _, tool := range tools {
		tm, _ := tool.(map[string]any)
		byName[tm["name"].(string)] = tm
	}
	for name, scopes := range want {
		tm, ok := byName[name]
		if !ok {
			r.t.Fatalf("%s: tool %s missing", label, name)
		}
		ss, _ := tm["securitySchemes"].([]any)
		if len(ss) != 1 {
			r.t.Fatalf("%s: tool %s securitySchemes %v", label, name, ss)
		}
		gotScopes := []string{}
		for _, sc := range ss[0].(map[string]any)["scopes"].([]any) {
			gotScopes = append(gotScopes, sc.(string))
		}
		if fmt.Sprint(gotScopes) != fmt.Sprint(scopes) {
			r.t.Fatalf("%s: tool %s scopes %v, want %v", label, name, gotScopes, scopes)
		}
	}
}

// --- the driver, mirroring scenario.py's run() subset

func newHub(t *testing.T) (*replay, *oauth.Server) {
	t.Helper()
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	st, err := store.New(filepath.Join(dir, "hub.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	tok, _ := store.NewToken()
	if err := st.Provision("dot", []string{"grok-bot", "lighthouse"}, tok); err != nil {
		t.Fatal(err)
	}
	tok2, _ := store.NewToken()
	if err := st.Provision("grok-bot", []string{"dot"}, tok2); err != nil {
		t.Fatal(err)
	}
	authFile := filepath.Join(dir, "auth.json")
	rec, _ := oauth.HashPassword(password)
	authJSON, _ := json.Marshal(map[string]any{"password": rec, "totp_seed": seed})
	if err := os.WriteFile(authFile, authJSON, 0600); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := &replay{t: t, base: "http://" + ln.Addr().String(), now: 1791900000.0 + 13*3600}
	oa, err := oauth.New(st.DB(), oauth.Config{
		Issuer: r.base, Peer: "dot", AuthFile: authFile,
		RedirectExact: []string{redirect},
	})
	if err != nil {
		t.Fatal(err)
	}
	oa.Now = func() time.Time { return time.Unix(int64(r.now), 0) }
	oh := &oauth.Handler{Server: oa, Limiter: oa.NewLimiter()}
	mh := &mcp.Handler{Server: &mcp.Server{
		Store: st, OAuth: oa, Events: events.New(st.DB(), &events.SafeHTTP{AllowInsecure: true}),
		Version: "test", Limiter: oa.NewLimiter(),
	}}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, rq *http.Request) {
		if rq.URL.Path == "/mcp" {
			mh.ServeHTTP(w, rq)
			return
		}
		oh.ServeHTTP(w, rq)
	}))
	_ = srv.Listener.Close()
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)
	return r, oa
}

func noRedirectClient() *http.Client {
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}

func (r *replay) do(method, path string, body io.Reader, ctype string, headers map[string]string) (int, http.Header, []byte) {
	r.t.Helper()
	req, err := http.NewRequest(method, r.base+path, body)
	if err != nil {
		r.t.Fatal(err)
	}
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := noRedirectClient().Do(req)
	if err != nil {
		r.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, raw
}

func (r *replay) rpc(token, method string, params any) (int, http.Header, []byte) {
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	h := map[string]string{"Mcp-Method": method}
	if token != "" {
		h["Authorization"] = "Bearer " + token
	}
	return r.do("POST", "/mcp", strings.NewReader(string(b)), "application/json", h)
}

// login mirrors scenario.py's login(): GET the form, POST the credentials.
// It returns the two responses.
func (r *replay) login(cid, verifier, pw, xff string) (getResp, postResp response) {
	chalSum := sha256.Sum256([]byte(verifier))
	q := url.Values{"response_type": {"code"}, "client_id": {cid}, "redirect_uri": {redirect},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(chalSum[:])},
		"code_challenge_method": {"S256"}, "state": {"st"}, "resource": {r.base + "/mcp"},
		"scope": {"messages:read messages:send events:subscribe"}}
	st, hd, body := r.do("GET", "/oauth/authorize?"+q.Encode(), nil, "", nil)
	getResp = response{st, hd, body}
	m := regexp.MustCompile(`name="rid" value="([^"]+)"`).FindStringSubmatch(string(body))
	if m == nil {
		r.t.Fatalf("no rid in login page (status %d)", st)
	}
	form := url.Values{"rid": {m[1]}, "password": {pw}, "action": {"approve"},
		"totp": {oauth.TOTPAt(seed, int64(r.now)/30)}}
	h := map[string]string{}
	if xff != "" {
		h["X-Forwarded-For"] = xff
	}
	st, hd, body = r.do("POST", "/oauth/authorize", strings.NewReader(form.Encode()),
		"application/x-www-form-urlencoded", h)
	postResp = response{st, hd, body}
	return
}

type response struct {
	status int
	header http.Header
	body   []byte
}

func (r *replay) locationCode(h http.Header) string {
	u, err := url.Parse(h.Get("Location"))
	if err != nil {
		r.t.Fatal(err)
	}
	return u.Query().Get("code")
}

func (r *replay) tokenForm(form url.Values) (int, http.Header, []byte) {
	return r.do("POST", "/oauth/token", strings.NewReader(form.Encode()),
		"application/x-www-form-urlencoded", nil)
}

func TestGoldenReplay(t *testing.T) {
	sc := loadScenario(t)
	r, _ := newHub(t)
	steps := sc.Steps
	i := 0
	next := func() step {
		if i >= len(steps) {
			t.Fatalf("scenario exhausted at step %d", i)
		}
		s := steps[i]
		i++
		return s
	}
	check := func(s step, resp response) {
		t.Helper()
		r.check(s, resp.status, resp.header, resp.body)
	}
	doStep := func(method, path string, body io.Reader, ctype string, hdr map[string]string) response {
		st, hd, b := r.do(method, path, body, ctype, hdr)
		return response{st, hd, b}
	}

	// metadata + transport guards
	check(next(), doStep("GET", "/.well-known/oauth-authorization-server", nil, "", nil))
	check(next(), doStep("GET", "/.well-known/oauth-protected-resource", nil, "", nil))
	check(next(), doStep("GET", "/mcp", nil, "", nil))
	{
		st, hd, b := r.rpc("", "tools/list", map[string]any{})
		check(next(), response{st, hd, b})
		st, hd, b = r.rpc("dba_forged", "tools/list", map[string]any{})
		check(next(), response{st, hd, b})
	}

	// registration: bad redirect, then good
	check(next(), doStep("POST", "/oauth/register",
		strings.NewReader(`{"redirect_uris":["https://evil.example/cb"]}`), "application/json", nil))
	{
		resp := doStep("POST", "/oauth/register",
			strings.NewReader(`{"redirect_uris":["`+redirect+`"],"client_name":"golden"}`), "application/json", nil)
		check(next(), resp)
		var out map[string]any
		if err := json.Unmarshal(resp.body, &out); err != nil {
			t.Fatal(err)
		}
		r.cid = out["client_id"].(string)
	}

	// authorize error branches
	authz := func(extra map[string]string) response {
		q := url.Values{"response_type": {"code"}, "client_id": {r.cid}, "redirect_uri": {redirect},
			"code_challenge": {strings.Repeat("a", 43)}, "code_challenge_method": {"S256"}, "state": {"s"}}
		for k, v := range extra {
			q.Set(k, v)
		}
		return doStep("GET", "/oauth/authorize?"+q.Encode(), nil, "", nil)
	}
	check(next(), authz(map[string]string{"code_challenge_method": "plain"}))
	s := next()
	if s.Golden != 10 {
		t.Fatalf("step order: %d", s.Golden)
	}
	{
		q := url.Values{"response_type": {"code"}, "client_id": {r.cid}, "redirect_uri": {redirect},
			"code_challenge": {""}, "code_challenge_method": {"S256"}, "state": {"s"}}
		// url.Values drops nothing, but encodes empty value as "code_challenge="
		check(s, doStep("GET", "/oauth/authorize?"+q.Encode(), nil, "", nil))
	}
	check(next(), authz(map[string]string{"redirect_uri": "https://x.example/"}))

	// wrong password, then good login
	g, p := r.login(r.cid, strings.Repeat("v", 50), "wrong", "")
	check(next(), g)
	check(next(), p)
	g, p = r.login(r.cid, strings.Repeat("v", 50), password, "")
	check(next(), g)
	check(next(), p)
	code := r.locationCode(p.header)

	// token: wrong verifier, unknown code
	check(next(), responseFrom(r.tokenForm(url.Values{"grant_type": {"authorization_code"}, "code": {code},
		"client_id": {r.cid}, "redirect_uri": {redirect}, "code_verifier": {strings.Repeat("x", 50)}})))
	check(next(), responseFrom(r.tokenForm(url.Values{"grant_type": {"authorization_code"}, "code": {"fake"},
		"client_id": {r.cid}, "redirect_uri": {redirect}, "code_verifier": {strings.Repeat("x", 50)}})))

	// good login + code exchange, refresh rotation, replay revocation
	r.now += 31
	g, p = r.login(r.cid, strings.Repeat("w", 50), password, "")
	check(next(), g)
	check(next(), p)
	code = r.locationCode(p.header)
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {r.cid},
		"redirect_uri": {redirect}, "code_verifier": {strings.Repeat("w", 50)}, "resource": {r.base + "/mcp"}}
	resp := responseFrom(r.tokenForm(form))
	check(next(), resp)
	var tok1 map[string]any
	if err := json.Unmarshal(resp.body, &tok1); err != nil {
		t.Fatal(err)
	}
	resp = responseFrom(r.tokenForm(url.Values{"grant_type": {"refresh_token"}, "client_id": {r.cid},
		"refresh_token": {tok1["refresh_token"].(string)}}))
	check(next(), resp)
	var tok2 map[string]any
	if err := json.Unmarshal(resp.body, &tok2); err != nil {
		t.Fatal(err)
	}
	check(next(), responseFrom(r.tokenForm(url.Values{"grant_type": {"refresh_token"}, "client_id": {r.cid},
		"refresh_token": {tok1["refresh_token"].(string)}}))) // replay -> family revoked
	{
		st, hd, b := r.rpc(tok2["access_token"].(string), "ping", nil)
		check(next(), response{st, hd, b})
	}

	// third login, then the MCP method battery with its token
	r.now += 31
	g, p = r.login(r.cid, strings.Repeat("z", 50), password, "")
	check(next(), g)
	check(next(), p)
	code = r.locationCode(p.header)
	form.Set("code", code)
	form.Set("code_verifier", strings.Repeat("z", 50))
	resp = responseFrom(r.tokenForm(form))
	check(next(), resp)
	var tok map[string]any
	if err := json.Unmarshal(resp.body, &tok); err != nil {
		t.Fatal(err)
	}
	T := tok["access_token"].(string)

	rpcStep := func(method string, params any) response {
		st, hd, b := r.rpc(T, method, params)
		return response{st, hd, b}
	}
	callStep := func(tool string, args map[string]any) response {
		return rpcStep("tools/call", map[string]any{"name": tool, "arguments": args})
	}
	check(next(), rpcStep("server/discover", map[string]any{}))
	check(next(), rpcStep("initialize", map[string]any{"protocolVersion": "2025-06-18"}))
	check(next(), rpcStep("tools/list", map[string]any{}))
	check(next(), rpcStep("resources/list", map[string]any{}))
	check(next(), rpcStep("nope/nope", map[string]any{}))
	check(next(), callStep("nope", map[string]any{}))

	// tool argument errors + ACL
	check(next(), callStep("send_message", map[string]any{}))
	check(next(), callStep("send_message", map[string]any{"text": "hi", "to": "manus-cue"}))
	check(next(), callStep("send_message", map[string]any{"text": "hi", "bogus": 1}))
	check(next(), callStep("send_message", map[string]any{"text": strings.Repeat("x", 9000), "to": "grok-bot"}))
	check(next(), callStep("read_messages", map[string]any{"limit": 99}))
	check(next(), callStep("send_message", map[string]any{"text": "answer",
		"reply_to": "00000000-0000-4000-8000-000000000000"}))

	// login lockout per IP (behind a trusted proxy), then the Origin check
	for n := 1; n <= 6; n++ {
		r.now += 31
		g, p := r.login(r.cid, strings.Repeat("q", 50), "bad", "198.51.100.7")
		check(next(), g)
		check(next(), p)
	}
	r.now += 31
	g, p = r.login(r.cid, strings.Repeat("q", 50), password, "198.51.100.7")
	check(next(), g)
	check(next(), p)
	check(next(), doStep("POST", "/oauth/authorize", strings.NewReader("rid=x"),
		"application/x-www-form-urlencoded", map[string]string{"Origin": "https://evil.example"}))

	if i != len(steps) {
		t.Fatalf("driver stopped at step %d of %d", i, len(steps))
	}
}

func responseFrom(st int, hd http.Header, b []byte) response { return response{st, hd, b} }
