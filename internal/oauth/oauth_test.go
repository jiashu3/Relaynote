package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"relaynote/internal/store"
	"strings"
	"testing"
	"time"
)

const testSeed = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP" // golden fixture seed, not a secret
const testPassword = "test-password-not-a-secret"

type fixture struct {
	t      *testing.T
	srv    *Server
	http   *httptest.Server
	now    float64
	issuer string
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
	authFile := filepath.Join(dir, "auth.json")
	rec, err := HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(map[string]any{"password": rec, "totp_seed": testSeed})
	if err := os.WriteFile(authFile, data, 0600); err != nil {
		t.Fatal(err)
	}
	f := &fixture{t: t, now: 1791900000.0}
	srv, err := New(st.DB(), Config{
		Issuer:             "http://placeholder.invalid", // replaced after httptest starts
		Peer:               "dot",
		AuthFile:           authFile,
		RedirectExact:      []string{"http://127.0.0.1:18812/oauth-cb"},
		RedirectPatterns:   []string{`^https://chatgpt\.com/connector/oauth/[A-Za-z0-9_-]{1,128}$`},
		CIMDClientIDs:      []string{"https://chatgpt.com/oauth/client.json"},
		CIMDClientPatterns: []string{`^https://chatgpt\.com/oauth/[A-Za-z0-9_-]{1,128}/client\.json$`},
	})
	if err != nil {
		t.Fatal(err)
	}
	srv.Now = func() time.Time { return time.Unix(int64(f.now), 0) }
	f.srv = srv
	h := &Handler{Server: srv, Limiter: srv.NewLimiter()}
	f.http = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(f.http.Close)
	f.issuer = f.http.URL
	f.srv.cfg.Issuer = f.issuer
	f.srv.resource = f.issuer + "/mcp"
	return f
}

func (f *fixture) adv(sec float64) { f.now += sec }

// login runs GET + POST /oauth/authorize and returns the POST response.
func (f *fixture) login(cid, verifier, password, xff string) *httptest.ResponseRecorder {
	f.t.Helper()
	chal := base64.RawURLEncoding.EncodeToString(sha256sum(verifier))
	q := url.Values{
		"response_type": {"code"}, "client_id": {cid},
		"redirect_uri": {"http://127.0.0.1:18812/oauth-cb"}, "code_challenge": {chal},
		"code_challenge_method": {"S256"}, "state": {"st"},
		"resource": {f.issuer + "/mcp"}, "scope": {"messages:read messages:send events:subscribe"},
	}
	resp, err := http.Get(f.http.URL + "/oauth/authorize?" + q.Encode())
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	page := string(must(io.ReadAll(resp.Body)))
	m := regexp.MustCompile(`name="rid" value="([^"]+)"`).FindStringSubmatch(page)
	if m == nil {
		f.t.Fatalf("no rid in login page (status %d)", resp.StatusCode)
	}
	form := url.Values{"rid": {m[1]}, "password": {password}, "action": {"approve"},
		"totp": {TOTPAt(testSeed, int64(f.now)/30)}}
	req, _ := http.NewRequest("POST", f.http.URL+"/oauth/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	resp2, err := noRedirect().Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp2.Body.Close()
	rec := httptest.NewRecorder()
	rec.Code = resp2.StatusCode
	rec.HeaderMap = resp2.Header
	rec.Body.Write(must(io.ReadAll(resp2.Body)))
	return rec
}

func noRedirect() *http.Client {
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}

func sha256sum(s string) []byte {
	sum := sha256.Sum256([]byte(s))
	return sum[:]
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func locationCode(t *testing.T, loc string) string {
	t.Helper()
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatal(err)
	}
	code := u.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in %q", loc)
	}
	return code
}

func registerClient(t *testing.T, base string) string {
	t.Helper()
	body := `{"redirect_uris":["http://127.0.0.1:18812/oauth-cb"],"client_name":"golden"}`
	resp, err := http.Post(base+"/oauth/register", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 201 {
		t.Fatalf("register: status %d", resp.StatusCode)
	}
	var out struct {
		ClientID string `json:"client_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out.ClientID, "dcr_") {
		t.Fatalf("client_id %q lacks dcr_ prefix", out.ClientID)
	}
	return out.ClientID
}

func tokenForm(t *testing.T, base string, form url.Values) (int, map[string]any) {
	t.Helper()
	resp, err := http.Post(base+"/oauth/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestMetadata(t *testing.T) {
	f := newFixture(t)
	for _, path := range []string{"/.well-known/oauth-authorization-server", "/.well-known/oauth-protected-resource"} {
		resp, err := http.Get(f.http.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("%s: %d", path, resp.StatusCode)
		}
	}
	md := f.srv.ASMetadata()
	if md["issuer"] != f.issuer || md["token_endpoint"] != f.issuer+"/oauth/token" {
		t.Fatalf("bad metadata: %v", md)
	}
}

func TestRegisterErrors(t *testing.T) {
	f := newFixture(t)
	resp, err := http.Post(f.http.URL+"/oauth/register", "application/json",
		strings.NewReader(`{"redirect_uris":["https://evil.example/cb"]}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if resp.StatusCode != 400 || out["error"] != "invalid_redirect_uri" {
		t.Fatalf("%d %v", resp.StatusCode, out)
	}
}

func TestAuthorizeErrorBranches(t *testing.T) {
	f := newFixture(t)
	cid := registerClient(t, f.http.URL)
	base := url.Values{"response_type": {"code"}, "client_id": {cid},
		"redirect_uri": {"http://127.0.0.1:18812/oauth-cb"}, "code_challenge": {strings.Repeat("a", 43)},
		"code_challenge_method": {"S256"}, "state": {"s"}}

	// plain challenge method -> redirect invalid_request
	q := url.Values{}
	for k, v := range base {
		q[k] = v
	}
	q.Set("code_challenge_method", "plain")
	resp, err := noRedirect().Get(f.http.URL + "/oauth/authorize?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	loc := resp.Header.Get("Location")
	if resp.StatusCode != 302 || !strings.Contains(loc, "error=invalid_request") ||
		!strings.Contains(loc, "state=s") || !strings.Contains(loc, "iss=") {
		t.Fatalf("%d %q", resp.StatusCode, loc)
	}

	// unknown redirect -> 400 page, never a redirect
	q.Set("code_challenge_method", "S256")
	q.Set("redirect_uri", "https://x.example/")
	resp, err = noRedirect().Get(f.http.URL + "/oauth/authorize?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	body := string(must(io.ReadAll(resp.Body)))
	resp.Body.Close()
	if resp.StatusCode != 400 || !strings.Contains(body, "unknown client or redirect_uri not allowed") {
		t.Fatalf("%d %q", resp.StatusCode, body)
	}
}

func TestTokenFlowAndReplayRevocation(t *testing.T) {
	f := newFixture(t)
	cid := registerClient(t, f.http.URL)

	verifier := strings.Repeat("v", 50)
	// wrong password -> retry page
	rec := f.login(cid, verifier, "wrong", "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "口令或验证码不正确。") {
		t.Fatalf("wrong password: %d", rec.Code)
	}
	// good login -> 302 with code
	rec = f.login(cid, verifier, testPassword, "")
	if rec.Code != 302 {
		t.Fatalf("login: %d %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Set-Cookie") == "" {
		t.Fatal("no device cookie on success")
	}
	code := locationCode(t, rec.Header().Get("Location"))

	// wrong verifier -> invalid_grant, code burned
	st, out := tokenForm(t, f.http.URL, url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "client_id": {cid},
		"redirect_uri": {"http://127.0.0.1:18812/oauth-cb"}, "code_verifier": {strings.Repeat("x", 50)}})
	if st != 400 || out["error"] != "invalid_grant" || out["error_description"] != "PKCE verification failed" {
		t.Fatalf("%d %v", st, out)
	}
	// replay of the burned code: still invalid_grant
	st, out = tokenForm(t, f.http.URL, url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "client_id": {cid},
		"redirect_uri": {"http://127.0.0.1:18812/oauth-cb"}, "code_verifier": {verifier}})
	if st != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("%d %v", st, out)
	}
	// unknown code
	st, out = tokenForm(t, f.http.URL, url.Values{
		"grant_type": {"authorization_code"}, "code": {"fake"}, "client_id": {cid},
		"redirect_uri": {"http://127.0.0.1:18812/oauth-cb"}, "code_verifier": {strings.Repeat("x", 50)}})
	if st != 400 || out["error_description"] != "unknown code" {
		t.Fatalf("%d %v", st, out)
	}

	// fresh login (TOTP step must advance), good exchange
	f.adv(31)
	rec = f.login(cid, strings.Repeat("w", 50), testPassword, "")
	code = locationCode(t, rec.Header().Get("Location"))
	st, tok1 := tokenForm(t, f.http.URL, url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "client_id": {cid},
		"redirect_uri": {"http://127.0.0.1:18812/oauth-cb"}, "code_verifier": {strings.Repeat("w", 50)},
		"resource": {f.issuer + "/mcp"}})
	if st != 200 || tok1["access_token"] == nil || tok1["expires_in"] != 3600.0 {
		t.Fatalf("%d %v", st, tok1)
	}

	// refresh rotates; replay of the old refresh token revokes the family
	st, tok2 := tokenForm(t, f.http.URL, url.Values{
		"grant_type": {"refresh_token"}, "client_id": {cid}, "refresh_token": {tok1["refresh_token"].(string)}})
	if st != 200 {
		t.Fatalf("refresh: %d %v", st, tok2)
	}
	st, out = tokenForm(t, f.http.URL, url.Values{
		"grant_type": {"refresh_token"}, "client_id": {cid}, "refresh_token": {tok1["refresh_token"].(string)}})
	if st != 400 || out["error_description"] != "refresh token already used" {
		t.Fatalf("replay: %d %v", st, out)
	}
	// the rotated access token is now revoked too
	if id := f.srv.VerifyAccess(tok2["access_token"].(string)); id != nil {
		t.Fatalf("family not revoked: %v", id)
	}

	// unsupported grant and client_secret rejection
	st, out = tokenForm(t, f.http.URL, url.Values{"grant_type": {"password"}, "client_id": {cid}})
	if st != 400 || out["error"] != "unsupported_grant_type" {
		t.Fatalf("%d %v", st, out)
	}
	st, out = tokenForm(t, f.http.URL, url.Values{"grant_type": {"refresh_token"}, "client_id": {cid},
		"client_secret": {"x"}, "refresh_token": {"y"}})
	if st != 401 || out["error"] != "invalid_client" {
		t.Fatalf("%d %v", st, out)
	}
}

func TestLoginLockoutPerIP(t *testing.T) {
	f := newFixture(t)
	cid := registerClient(t, f.http.URL)
	verifier := strings.Repeat("q", 50)
	for i := 0; i < 5; i++ {
		f.adv(31)
		rec := f.login(cid, verifier, "bad", "198.51.100.7")
		if !strings.Contains(rec.Body.String(), "口令或验证码不正确。") {
			t.Fatalf("attempt %d: %s", i, rec.Body.String())
		}
	}
	// 6th attempt from that IP is locked, even with the right password
	f.adv(31)
	rec := f.login(cid, verifier, testPassword, "198.51.100.7")
	if !strings.Contains(rec.Body.String(), "已锁定 15 分钟") {
		t.Fatalf("not locked: %s", rec.Body.String())
	}
	// a different IP is unaffected
	rec = f.login(cid, verifier, testPassword, "")
	if rec.Code != 302 {
		t.Fatalf("other IP affected: %d", rec.Code)
	}
	// the lock expires
	f.adv(LockFor + 1)
	rec = f.login(cid, verifier, testPassword, "198.51.100.7")
	if rec.Code != 302 {
		t.Fatalf("lock did not expire: %d", rec.Code)
	}
}

func TestAuthorizeOriginCheck(t *testing.T) {
	f := newFixture(t)
	req, _ := http.NewRequest("POST", f.http.URL+"/oauth/authorize", strings.NewReader("rid=x"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://evil.example")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("%d", resp.StatusCode)
	}
}

func TestLockKey(t *testing.T) {
	if LockKey("198.51.100.7") != "ip4:198.51.100.7" {
		t.Fatal("v4")
	}
	if got := LockKey("2001:db8:dead:beef::1"); got != "ip6:2001:db8:dead:beef::/64" {
		t.Fatalf("v6: %s", got)
	}
	if LockKey("::ffff:1.2.3.4") != "ip4:1.2.3.4" {
		t.Fatal("mapped")
	}
	if LockKey("junk") != "ip:invalid" {
		t.Fatal("invalid")
	}
}

func TestTOTP(t *testing.T) {
	// RFC 6238 SHA-1 test key "12345678901234567890" in base32.
	seed := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	if got := TOTPAt(seed, 0x23523EC); got != "081804" {
		t.Fatalf("TOTP: %s", got)
	}
	if got := TOTPAt(seed, 1); got != "287082" {
		t.Fatalf("TOTP: %s", got)
	}
}
