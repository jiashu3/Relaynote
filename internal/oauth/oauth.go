// Package oauth implements Relaynote's optional OAuth 2.1 authorization
// server: PKCE S256 only, public clients (dynamic registration and
// client-id metadata document allow-listing), authorization codes, refresh
// token rotation with whole-family revocation on replay, and login rate
// limiting. It is a generic port of dot-bridge's oauth.py with the same
// error codes and statuses. State lives in the hub's bbolt database in
// dedicated buckets. Everything here is default-off: serve mounts it only
// with --oauth-issuer.
//
// One intentional divergence from oauth.py: password hashes use PBKDF2
// (stdlib crypto/pbkdf2) instead of scrypt, so no new module dependency is
// needed; the auth file format is Relaynote's own either way.
package oauth

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Login rate limiting (same values as oauth.py): LockFails failures from one
// lock key (IP, IPv6 /64, or trusted device) inside LockWindow lock that key
// for LockFor; a lenient global throttle pauses untrusted logins while
// GlobalFails failures sit in the last GlobalWindow.
const (
	LockFails, LockWindow, LockFor = 5, 900, 900
	GlobalFails, GlobalWindow      = 60, 3600
	DeviceTTL                      = 90 * 86400
	CodeTTL, ReqTTL                = 300, 600
)

// DeviceCookie names the trusted-device cookie, issued only after a
// successful password+TOTP login.
const DeviceCookie = "rndev"

// Scopes are the only scopes this authorization server issues.
var Scopes = []string{"messages:read", "messages:send", "events:subscribe"}

var (
	challengePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43,128}$`)
	verifierPattern  = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)
	devicePattern    = regexp.MustCompile(`^d1\.([0-9a-f]{24})\.([0-9a-f]{32})$`)
	cimdPathPattern  = regexp.MustCompile(`^/oauth/([A-Za-z0-9_-]{1,128})/client\.json$`)
)

var (
	bucketClients  = []byte("oauth_clients")
	bucketRequests = []byte("oauth_requests")
	bucketCodes    = []byte("oauth_codes")
	bucketTokens   = []byte("oauth_tokens")
	bucketKV       = []byte("oauth_kv")
	bucketDevices  = []byte("oauth_devices")
	bucketFailures = []byte("oauth_login_failures")
)

// Error is an OAuth protocol error; Status and Err map onto the HTTP
// response exactly as oauth.py's OAuthError does.
type Error struct {
	Err    string
	Desc   string
	Status int
}

func (e *Error) Error() string { return e.Err + ": " + e.Desc }

func oauthError(err, desc string, status int) *Error {
	if status == 0 {
		status = 400
	}
	return &Error{Err: err, Desc: desc, Status: status}
}

// Config configures the authorization server. Issuer is the public base URL
// (no trailing slash); the protected resource is Issuer + "/mcp".
type Config struct {
	Issuer             string   `json:"-"`
	Peer               string   `json:"peer"` // hub peer the access tokens act as
	AuthFile           string   `json:"auth_file"`
	RedirectExact      []string `json:"redirect_exact"`
	RedirectPatterns   []string `json:"redirect_patterns"`
	CIMDClientIDs      []string `json:"cimd_client_ids"`
	CIMDClientPatterns []string `json:"cimd_client_patterns"`
	AccessTTL          int      `json:"access_ttl_sec"`  // default 3600
	RefreshTTL         int      `json:"refresh_ttl_sec"` // default 30 days
	MaxDCRClients      int      `json:"max_dcr_clients"` // default 20
	TrustedProxies     []string `json:"trusted_proxies"` // default ["127.0.0.1"]
}

// Server is the authorization server. Not safe to copy after first use.
type Server struct {
	cfg              Config
	db               *bolt.DB
	resource         string
	redirectPatterns []*regexp.Regexp
	cimdPatterns     []*regexp.Regexp
	loginMu          sync.Mutex // TOTP step check + update must be atomic

	// Now is an optional clock for deterministic tests.
	Now func() time.Time
}

// New validates the config and returns the server. db must be the hub's
// store database (see store.Store.DB).
func New(db *bolt.DB, cfg Config) (*Server, error) {
	if cfg.Issuer == "" {
		return nil, errors.New("oauth: issuer is required")
	}
	if cfg.Peer == "" {
		return nil, errors.New("oauth: peer is required")
	}
	cfg.Issuer = strings.TrimSuffix(cfg.Issuer, "/")
	if cfg.AccessTTL <= 0 {
		cfg.AccessTTL = 3600
	}
	if cfg.RefreshTTL <= 0 {
		cfg.RefreshTTL = 30 * 86400
	}
	if cfg.MaxDCRClients <= 0 {
		cfg.MaxDCRClients = 20
	}
	if len(cfg.TrustedProxies) == 0 {
		cfg.TrustedProxies = []string{"127.0.0.1"}
	}
	s := &Server{cfg: cfg, db: db, resource: cfg.Issuer + "/mcp"}
	for _, p := range cfg.RedirectPatterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("oauth: redirect pattern: %w", err)
		}
		s.redirectPatterns = append(s.redirectPatterns, re)
	}
	for _, p := range cfg.CIMDClientPatterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("oauth: CIMD client pattern: %w", err)
		}
		s.cimdPatterns = append(s.cimdPatterns, re)
	}
	return s, nil
}

func (s *Server) now() float64 {
	t := time.Now()
	if s.Now != nil {
		t = s.Now()
	}
	return float64(t.Unix()) + float64(t.Nanosecond())/1e9
}

// Issuer is the public base URL; Resource is the protected resource URL.
func (s *Server) Issuer() string   { return s.cfg.Issuer }
func (s *Server) Resource() string { return s.resource }

// TrustedProxies are the TCP peers allowed to set X-Forwarded-For.
func (s *Server) TrustedProxies() []string { return s.cfg.TrustedProxies }

// ------------------------------------------------------------------ metadata

// ProtectedResourceMetadata is the RFC 9728 document.
func (s *Server) ProtectedResourceMetadata() map[string]any {
	return map[string]any{
		"resource": s.resource, "authorization_servers": []string{s.cfg.Issuer},
		"scopes_supported": Scopes, "bearer_methods_supported": []string{"header"},
		"resource_name": "Relaynote hub",
	}
}

// ASMetadata is the RFC 8414 document.
func (s *Server) ASMetadata() map[string]any {
	b := s.cfg.Issuer
	return map[string]any{
		"issuer": b, "authorization_endpoint": b + "/oauth/authorize",
		"token_endpoint": b + "/oauth/token", "registration_endpoint": b + "/oauth/register",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none"},
		"scopes_supported":                      Scopes, "authorization_response_iss_parameter_supported": true,
		"client_id_metadata_document_supported": true,
	}
}

// WWWAuthenticate builds the Bearer challenge for the MCP endpoint.
func (s *Server) WWWAuthenticate(err, desc, scope string) string {
	v := fmt.Sprintf(`Bearer resource_metadata="%s/.well-known/oauth-protected-resource"`, s.cfg.Issuer)
	if scope != "" {
		v += fmt.Sprintf(`, scope="%s"`, scope)
	}
	if err != "" {
		if desc == "" {
			desc = err
		}
		v += fmt.Sprintf(`, error="%s", error_description="%s"`, err, desc)
	}
	return v
}

// ------------------------------------------------------------------ password + TOTP

// PasswordRecord is a salted PBKDF2-SHA256 password hash for the auth file.
type PasswordRecord struct {
	Alg  string `json:"alg"` // "pbkdf2-sha256"
	Iter int    `json:"iter"`
	Salt string `json:"salt"` // standard base64
	Hash string `json:"hash"`
}

// HashPassword hashes a password for storage in the auth file.
func HashPassword(pw string) (PasswordRecord, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return PasswordRecord{}, err
	}
	dk, err := pbkdf2.Key(sha256.New, pw, salt, 210000, 32)
	if err != nil {
		return PasswordRecord{}, err
	}
	return PasswordRecord{Alg: "pbkdf2-sha256", Iter: 210000,
		Salt: base64.StdEncoding.EncodeToString(salt), Hash: base64.StdEncoding.EncodeToString(dk)}, nil
}

func checkPassword(pw string, rec *PasswordRecord) bool {
	if rec == nil || rec.Alg != "pbkdf2-sha256" || rec.Iter < 1 || rec.Iter > 1<<22 {
		return false
	}
	salt, err := base64.StdEncoding.DecodeString(rec.Salt)
	if err != nil {
		return false
	}
	want, err := base64.StdEncoding.DecodeString(rec.Hash)
	if err != nil {
		return false
	}
	dk, err := pbkdf2.Key(sha256.New, pw, salt, rec.Iter, len(want))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(dk, want) == 1
}

// authFile is the login credential document behind Config.AuthFile.
type authFile struct {
	Password *PasswordRecord `json:"password"`
	TOTPSeed string          `json:"totp_seed"`
}

func (s *Server) loadAuth() *authFile {
	if s.cfg.AuthFile == "" {
		return nil
	}
	data, err := os.ReadFile(s.cfg.AuthFile)
	if err != nil {
		return nil
	}
	var a authFile
	if err := json.Unmarshal(data, &a); err != nil {
		return nil
	}
	return &a
}

// TOTPAt returns the RFC 6238 SHA1/30s/6-digit code for a step; exported for
// tests and setup tooling.
func TOTPAt(seedB32 string, step int64) string {
	seed := strings.ToUpper(seedB32)
	seed += strings.Repeat("=", -len(seed)%8)
	key, err := base32.StdEncoding.DecodeString(seed)
	if err != nil {
		return ""
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(step))
	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	d := mac.Sum(nil)
	off := d[len(d)-1] & 0x0f
	val := binary.BigEndian.Uint32(d[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", val%1000000)
}

// totpMatch returns the matched step (must be > lastStep) or -1.
func totpMatch(seedB32, code string, now float64, lastStep int64) int64 {
	if ok, _ := regexp.MatchString(`^\d{6}$`, code); !ok {
		return -1
	}
	cur := int64(now) / 30
	for _, step := range []int64{cur - 1, cur, cur + 1} {
		if step > lastStep && subtle.ConstantTimeCompare([]byte(TOTPAt(seedB32, step)), []byte(code)) == 1 {
			return step
		}
	}
	return -1
}

// ------------------------------------------------------------------ clients

func (s *Server) redirectAllowed(uri string) bool {
	for _, e := range s.cfg.RedirectExact {
		if uri == e {
			return true
		}
	}
	for _, p := range s.redirectPatterns {
		if p.MatchString(uri) {
			return true
		}
	}
	return false
}

type client struct {
	Kind         string   `json:"kind"` // "dcr" or "cimd"
	RedirectURIs []string `json:"redirect_uris"`
	ClientName   string   `json:"client_name"`
	CreatedAt    float64  `json:"created_at"`
}

// clientRedirects returns the client's registered redirect URIs, the sentinel
// ["*allow-list*"] for allow-listed client-id metadata documents (the
// document is never fetched), or nil for an unknown client.
func (s *Server) clientRedirects(clientID string) ([]string, error) {
	if len(clientID) == 0 || len(clientID) > 512 {
		return nil, nil
	}
	for _, id := range s.cfg.CIMDClientIDs {
		if clientID == id {
			return []string{"*allow-list*"}, nil
		}
	}
	for _, p := range s.cimdPatterns {
		if p.MatchString(clientID) {
			return []string{"*allow-list*"}, nil
		}
	}
	var reds []string
	err := s.db.View(func(tx *bolt.Tx) error {
		data := tx.Bucket(bucketClients).Get([]byte(clientID))
		if data == nil {
			return nil
		}
		var c client
		if err := json.Unmarshal(data, &c); err != nil {
			return err
		}
		reds = c.RedirectURIs
		return nil
	})
	return reds, err
}

func (s *Server) clientRedirectOK(clientID, redirectURI string) bool {
	reds, err := s.clientRedirects(clientID)
	if err != nil || reds == nil || !s.redirectAllowed(redirectURI) {
		return false
	}
	if len(reds) == 1 && reds[0] == "*allow-list*" {
		// A CIMD client id of the form .../oauth/<id>/client.json pairs with
		// its own callback-id redirect on the same host.
		if u, err := url.Parse(clientID); err == nil {
			if m := cimdPathPattern.FindStringSubmatch(u.Path); m != nil {
				return redirectURI == u.Scheme+"://"+u.Host+"/connector/oauth/"+m[1]
			}
		}
		return true
	}
	for _, r := range reds {
		if redirectURI == r {
			return true
		}
	}
	return false
}

// Register implements RFC 7591 dynamic client registration for public
// clients whose redirect URIs are on the allow-list.
func (s *Server) Register(body map[string]any) (map[string]any, error) {
	if body == nil {
		return nil, oauthError("invalid_client_metadata", "body must be a JSON object", 400)
	}
	rawReds, ok := body["redirect_uris"].([]any)
	reds := []string{}
	for _, r := range rawReds {
		s, ok := r.(string)
		if !ok {
			reds = nil
			break
		}
		reds = append(reds, s)
	}
	if !ok || len(reds) == 0 || len(reds) > 5 {
		return nil, oauthError("invalid_redirect_uri", "redirect_uris must be allow-listed connector callbacks", 400)
	}
	for _, r := range reds {
		if !s.redirectAllowed(r) {
			return nil, oauthError("invalid_redirect_uri", "redirect_uris must be allow-listed connector callbacks", 400)
		}
	}
	if m, ok := body["token_endpoint_auth_method"]; ok && m != "none" {
		return nil, oauthError("invalid_client_metadata", "only token_endpoint_auth_method=none is supported", 400)
	}
	name, _ := body["client_name"].(string)
	if len(name) > 100 {
		name = name[:100]
	}
	cid, err := randomString(18)
	if err != nil {
		return nil, err
	}
	cid = "dcr_" + cid
	now := s.now()
	err = s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketClients)
		n := 0
		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var cl client
			if json.Unmarshal(v, &cl) == nil && cl.Kind == "dcr" {
				n++
			}
		}
		if n >= s.cfg.MaxDCRClients {
			return oauthError("invalid_client_metadata", "client registration limit reached", 400)
		}
		return putJSON(b, []byte(cid), client{Kind: "dcr", RedirectURIs: reds, ClientName: name, CreatedAt: now})
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"client_id": cid, "client_id_issued_at": int64(now), "redirect_uris": reds,
		"token_endpoint_auth_method": "none", "grant_types": []string{"authorization_code", "refresh_token"},
		"response_types": []string{"code"}, "client_name": name,
	}, nil
}

// ------------------------------------------------------------------ authorize

type authRequest struct {
	ClientID    string `json:"client_id"`
	RedirectURI string `json:"redirect_uri"`
	State       string `json:"state"`
	Challenge   string `json:"challenge"`
	Scope       string `json:"scope"`
	Resource    string `json:"resource"`
}

// RedirectURL appends response parameters to a redirect URI; iss is in every
// response, success or error (RFC 9207).
func (s *Server) RedirectURL(uri string, params map[string]string) string {
	q := url.Values{}
	for k, v := range params {
		if v != "" {
			q.Set(k, v)
		}
	}
	q.Set("iss", s.cfg.Issuer)
	sep := "?"
	if strings.Contains(uri, "?") {
		sep = "&"
	}
	return uri + sep + q.Encode()
}

// StartAuthorize validates an authorization request. It returns ("page",
// rid) to render the login form or ("redirect", url) for an in-protocol
// error redirect; errors that must not redirect (bad client/redirect) come
// back as *Error.
func (s *Server) StartAuthorize(q map[string]string) (string, string, error) {
	clientID, redirectURI := q["client_id"], q["redirect_uri"]
	if !s.clientRedirectOK(clientID, redirectURI) {
		return "", "", oauthError("invalid_request", "unknown client or redirect_uri not allowed", 400)
	}
	errRedirect := func(e, d string) (string, string, error) {
		return "redirect", s.RedirectURL(redirectURI, map[string]string{
			"error": e, "error_description": d, "state": q["state"]}), nil
	}
	if q["response_type"] != "code" {
		return errRedirect("unsupported_response_type", "response_type must be code")
	}
	if q["code_challenge_method"] != "S256" || !challengePattern.MatchString(q["code_challenge"]) {
		return errRedirect("invalid_request", "PKCE S256 code_challenge required")
	}
	resource := q["resource"]
	if resource == "" {
		resource = s.resource
	}
	if resource != s.resource {
		return errRedirect("invalid_target", "unknown resource")
	}
	scope := q["scope"]
	if scope == "" {
		scope = strings.Join(Scopes, " ")
	}
	scopes := strings.Fields(scope)
	if len(scopes) == 0 {
		return errRedirect("invalid_scope", "unsupported scope")
	}
	for _, sc := range scopes {
		ok := false
		for _, known := range Scopes {
			if sc == known {
				ok = true
			}
		}
		if !ok {
			return errRedirect("invalid_scope", "unsupported scope")
		}
	}
	auth := s.loadAuth()
	if auth == nil || auth.TOTPSeed == "" || auth.Password == nil {
		return errRedirect("temporarily_unavailable", "login not configured yet")
	}
	rid, err := randomString(24)
	if err != nil {
		return "", "", err
	}
	params := authRequest{ClientID: clientID, RedirectURI: redirectURI, State: q["state"],
		Challenge: q["code_challenge"], Scope: strings.Join(scopes, " "), Resource: resource}
	err = s.db.Update(func(tx *bolt.Tx) error {
		return putJSON(tx.Bucket(bucketRequests), []byte(rid), struct {
			Params    authRequest `json:"params"`
			ExpiresAt float64     `json:"expires_at"`
		}{params, s.now() + ReqTTL})
	})
	if err != nil {
		return "", "", err
	}
	return "page", rid, nil
}

// RequestParams returns a pending authorization request, or nil when unknown
// or expired.
func (s *Server) RequestParams(rid string) *authRequest {
	var out *authRequest
	_ = s.db.View(func(tx *bolt.Tx) error {
		data := tx.Bucket(bucketRequests).Get([]byte(rid))
		if data == nil {
			return nil
		}
		var r struct {
			Params    authRequest `json:"params"`
			ExpiresAt float64     `json:"expires_at"`
		}
		if err := json.Unmarshal(data, &r); err != nil || r.ExpiresAt < s.now() {
			return nil
		}
		out = &r.Params
		return nil
	})
	return out
}

func (s *Server) dropRequest(rid string) {
	_ = s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketRequests).Delete([]byte(rid))
	})
}

// ------------------------------------------------------------------ login rate limiting

// LockKey derives the rate-limit key for an IP: IPv6 collapses to its /64.
func LockKey(ip string) string {
	a := net.ParseIP(strings.TrimSpace(ip))
	if a == nil {
		return "ip:invalid"
	}
	if v4 := a.To4(); v4 != nil {
		return "ip4:" + v4.String()
	}
	mask := net.CIDRMask(64, 128)
	return "ip6:" + a.Mask(mask).String() + "/64"
}

func (s *Server) failureTimes(tx *bolt.Tx, key string, since float64) []float64 {
	out := []float64{}
	prefix := []byte(key + "\x00")
	c := tx.Bucket(bucketFailures).Cursor()
	for k, _ := c.Seek(prefix); k != nil && strings.HasPrefix(string(k), string(prefix)); k, _ = c.Next() {
		ts := float64(binary.BigEndian.Uint64(k[len(prefix):len(prefix)+8])) / 1e6
		if ts > since {
			out = append(out, ts)
		}
	}
	return out
}

func (s *Server) recordFailure(tx *bolt.Tx, key string, now float64) error {
	row := append([]byte(key+"\x00"), make([]byte, 12)...)
	binary.BigEndian.PutUint64(row[len(row)-12:len(row)-4], uint64(now*1e6))
	if _, err := rand.Read(row[len(row)-4:]); err != nil {
		return err
	}
	return tx.Bucket(bucketFailures).Put(row, []byte{})
}

func (s *Server) lockedUntil(key string) float64 {
	now := s.now()
	var rows []float64
	_ = s.db.View(func(tx *bolt.Tx) error {
		rows = s.failureTimes(tx, key, now-LockWindow-LockFor)
		return nil
	})
	// Locked if LockFails failures happened within any LockWindow and the last
	// of them is less than LockFor ago.
	for i := 0; i+LockFails-1 < len(rows); i++ {
		last := rows[i+LockFails-1]
		if last-rows[i] <= LockWindow && now-last < LockFor {
			return last + LockFor
		}
	}
	return 0
}

// globalThrottledUntil is a lenient throttle across all untrusted clients:
// untrusted logins pause while GlobalFails failures sit in the last
// GlobalWindow (self-healing: refused attempts are not counted).
func (s *Server) globalThrottledUntil() float64 {
	now := s.now()
	rows := []float64{}
	_ = s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketFailures).ForEach(func(k, _ []byte) error {
			idx := strings.IndexByte(string(k), 0)
			if idx < 0 {
				return nil
			}
			ts := float64(binary.BigEndian.Uint64(k[idx+1:idx+9])) / 1e6
			if ts > now-GlobalWindow {
				rows = append(rows, ts)
			}
			return nil
		})
	})
	if len(rows) < GlobalFails {
		return 0
	}
	sort.Float64s(rows)
	return rows[len(rows)-GlobalFails] + GlobalWindow
}

// ------------------------------------------------------------------ trusted devices

func (s *Server) deviceKey(tx *bolt.Tx) ([]byte, error) {
	b := tx.Bucket(bucketKV)
	if v := b.Get([]byte("device_key")); v != nil {
		k, err := hex.DecodeString(string(v))
		return k, err
	}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	if err := b.Put([]byte("device_key"), []byte(hex.EncodeToString(k))); err != nil {
		return nil, err
	}
	return k, nil
}

func (s *Server) deviceMAC(tx *bolt.Tx, devID string) (string, error) {
	k, err := s.deviceKey(tx)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, k)
	mac.Write([]byte("dev:" + devID))
	return hex.EncodeToString(mac.Sum(nil))[:32], nil
}

func (s *Server) issueDevice() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	devID := hex.EncodeToString(b)
	var cookie string
	err := s.db.Update(func(tx *bolt.Tx) error {
		if err := putJSON(tx.Bucket(bucketDevices), []byte(devID), struct {
			CreatedAt float64 `json:"created_at"`
			ExpiresAt float64 `json:"expires_at"`
		}{s.now(), s.now() + DeviceTTL}); err != nil {
			return err
		}
		mac, err := s.deviceMAC(tx, devID)
		if err != nil {
			return err
		}
		cookie = "d1." + devID + "." + mac
		return nil
	})
	return cookie, err
}

// checkDevice validates a trusted-device cookie and returns the device id.
func (s *Server) checkDevice(cookie string) string {
	m := devicePattern.FindStringSubmatch(cookie)
	if m == nil {
		return ""
	}
	ok := false
	_ = s.db.View(func(tx *bolt.Tx) error {
		want, err := s.deviceMAC(tx, m[1])
		if err != nil || subtle.ConstantTimeCompare([]byte(m[2]), []byte(want)) != 1 {
			return nil
		}
		data := tx.Bucket(bucketDevices).Get([]byte(m[1]))
		if data == nil {
			return nil
		}
		var d struct {
			ExpiresAt float64 `json:"expires_at"`
		}
		if json.Unmarshal(data, &d) == nil && d.ExpiresAt > s.now() {
			ok = true
		}
		return nil
	})
	if !ok {
		return ""
	}
	return m[1]
}

// DeviceCookieHeader builds the Set-Cookie value for a trusted device.
func (s *Server) DeviceCookieHeader(value string) string {
	secure := ""
	if strings.HasPrefix(s.cfg.Issuer, "https://") {
		secure = "; Secure"
	}
	return fmt.Sprintf("%s=%s; Path=/oauth/; Max-Age=%d; HttpOnly; SameSite=Lax%s",
		DeviceCookie, value, DeviceTTL, secure)
}

// ------------------------------------------------------------------ finish authorize

// FinishAuthorize processes the login form. It returns ("redirect", url,
// headers), ("retry", message, nil) or ("expired", message, nil).
func (s *Server) FinishAuthorize(form map[string]string, ip, deviceCookie string) (string, string, map[string]string, error) {
	rid := form["rid"]
	params := s.RequestParams(rid)
	if params == nil {
		return "expired", "登录请求已过期，请回到客户端重新连接。", nil, nil
	}
	if form["action"] == "deny" {
		s.dropRequest(rid)
		return "redirect", s.RedirectURL(params.RedirectURI, map[string]string{
			"error": "access_denied", "state": params.State}), nil, nil
	}
	s.loginMu.Lock()
	defer s.loginMu.Unlock()
	return s.finishLocked(form, ip, rid, params, s.checkDevice(deviceCookie))
}

func (s *Server) finishLocked(form map[string]string, ip, rid string, params *authRequest, device string) (string, string, map[string]string, error) {
	if s.RequestParams(rid) == nil {
		return "expired", "登录请求已过期，请回到客户端重新连接。", nil, nil
	}
	key := LockKey(ip)
	if device != "" {
		key = "dev:" + device
	}
	if s.lockedUntil(key) > s.now() {
		return "retry", "这台设备/网络失败次数过多，已锁定 15 分钟，请稍后再试。", nil, nil
	}
	if device == "" && s.globalThrottledUntil() > s.now() {
		return "retry", "最近登录失败太多（可能有人在猜口令），新设备暂时不能登录，请稍后再试；已登录过的浏览器不受影响。", nil, nil
	}
	auth := s.loadAuth()
	var pwOK bool
	if auth != nil {
		pwOK = checkPassword(form["password"], auth.Password)
	}
	var lastStep int64
	_ = s.db.View(func(tx *bolt.Tx) error {
		if v := tx.Bucket(bucketKV).Get([]byte("totp_last_step")); v != nil {
			lastStep, _ = strconv.ParseInt(string(v), 10, 64)
		}
		return nil
	})
	step := int64(-1)
	if auth != nil && auth.TOTPSeed != "" {
		step = totpMatch(auth.TOTPSeed, strings.TrimSpace(form["totp"]), s.now(), lastStep)
	}
	if !pwOK || step < 0 {
		err := s.db.Update(func(tx *bolt.Tx) error {
			return s.recordFailure(tx, key, s.now())
		})
		if err != nil {
			return "", "", nil, err
		}
		return "retry", "口令或验证码不正确。", nil, nil
	}
	code, err := randomString(32)
	if err != nil {
		return "", "", nil, err
	}
	family, err := randomHex(12)
	if err != nil {
		return "", "", nil, err
	}
	err = s.db.Update(func(tx *bolt.Tx) error {
		if err := putJSON(tx.Bucket(bucketCodes), []byte(sha256Hex(code)), authCode{
			ClientID: params.ClientID, RedirectURI: params.RedirectURI, Challenge: params.Challenge,
			Scope: params.Scope, Resource: params.Resource, Family: family,
			ExpiresAt: s.now() + CodeTTL,
		}); err != nil {
			return err
		}
		if err := tx.Bucket(bucketKV).Put([]byte("totp_last_step"), []byte(strconv.FormatInt(step, 10))); err != nil {
			return err
		}
		if err := tx.Bucket(bucketRequests).Delete([]byte(rid)); err != nil {
			return err
		}
		// Successful login clears the failure records for this device and IP.
		for _, k := range []string{key, LockKey(ip)} {
			prefix := []byte(k + "\x00")
			c := tx.Bucket(bucketFailures).Cursor()
			var doomed [][]byte
			for rk, _ := c.Seek(prefix); rk != nil && strings.HasPrefix(string(rk), string(prefix)); rk, _ = c.Next() {
				doomed = append(doomed, append([]byte{}, rk...))
			}
			for _, rk := range doomed {
				if err := tx.Bucket(bucketFailures).Delete(rk); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		return "", "", nil, err
	}
	cookie, err := s.issueDevice()
	if err != nil {
		return "", "", nil, err
	}
	return "redirect", s.RedirectURL(params.RedirectURI, map[string]string{
		"code": code, "state": params.State}), map[string]string{"Set-Cookie": s.DeviceCookieHeader(cookie)}, nil
}

// ------------------------------------------------------------------ token

type authCode struct {
	ClientID    string  `json:"client_id"`
	RedirectURI string  `json:"redirect_uri"`
	Challenge   string  `json:"challenge"`
	Scope       string  `json:"scope"`
	Resource    string  `json:"resource"`
	Family      string  `json:"family"`
	ExpiresAt   float64 `json:"expires_at"`
	Used        bool    `json:"used"`
}

type token struct {
	Type      string  `json:"type"` // "access" | "refresh"
	ClientID  string  `json:"client_id"`
	Scope     string  `json:"scope"`
	Resource  string  `json:"resource"`
	Family    string  `json:"family"`
	ExpiresAt float64 `json:"expires_at"`
	Revoked   bool    `json:"revoked"`
	Used      bool    `json:"used"`
	CreatedAt float64 `json:"created_at"`
}

// issue persists a fresh access+refresh pair inside tx.
func (s *Server) issue(tx *bolt.Tx, clientID, scope, resource, family string) (map[string]any, error) {
	at, err := randomString(32)
	if err != nil {
		return nil, err
	}
	rt, err := randomString(32)
	if err != nil {
		return nil, err
	}
	now := s.now()
	b := tx.Bucket(bucketTokens)
	if err := putJSON(b, []byte(sha256Hex("rna_"+at)), token{Type: "access", ClientID: clientID, Scope: scope,
		Resource: resource, Family: family, ExpiresAt: now + float64(s.cfg.AccessTTL), CreatedAt: now}); err != nil {
		return nil, err
	}
	if err := putJSON(b, []byte(sha256Hex("rnr_"+rt)), token{Type: "refresh", ClientID: clientID, Scope: scope,
		Resource: resource, Family: family, ExpiresAt: now + float64(s.cfg.RefreshTTL), CreatedAt: now}); err != nil {
		return nil, err
	}
	return map[string]any{
		"access_token": "rna_" + at, "token_type": "Bearer", "expires_in": s.cfg.AccessTTL,
		"refresh_token": "rnr_" + rt, "scope": scope,
	}, nil
}

// loadToken reads a token row by raw token value.
func loadToken(tx *bolt.Tx, raw, typ string) (*token, error) {
	data := tx.Bucket(bucketTokens).Get([]byte(sha256Hex(raw)))
	if data == nil {
		return nil, nil
	}
	var t token
	if err := json.Unmarshal(data, &t); err != nil {
		return nil, err
	}
	if t.Type != typ {
		return nil, nil
	}
	return &t, nil
}

// revokeFamily marks every token of a family revoked.
func revokeFamily(tx *bolt.Tx, family string, onlyType string) error {
	b := tx.Bucket(bucketTokens)
	return b.ForEach(func(k, v []byte) error {
		var t token
		if err := json.Unmarshal(v, &t); err != nil {
			return err
		}
		if t.Family == family && !t.Revoked && (onlyType == "" || t.Type == onlyType) {
			t.Revoked = true
			return putJSON(b, append([]byte{}, k...), t)
		}
		return nil
	})
}

// Token implements the token endpoint: authorization_code (with PKCE
// verification) and refresh_token (rotating; a replayed refresh token or
// authorization code revokes the whole family).
func (s *Server) Token(form map[string]string) (map[string]any, error) {
	clientID := form["client_id"]
	if form["client_secret"] != "" || form["client_assertion"] != "" {
		return nil, oauthError("invalid_client", "only public clients (none) are supported", 401)
	}
	reds, err := s.clientRedirects(clientID)
	if err != nil {
		return nil, err
	}
	if reds == nil {
		return nil, oauthError("invalid_client", "unknown client", 401)
	}
	switch form["grant_type"] {
	case "authorization_code":
		return s.tokenCode(clientID, form)
	case "refresh_token":
		return s.tokenRefresh(clientID, form)
	}
	return nil, oauthError("unsupported_grant_type", "grant_type not supported", 400)
}

func (s *Server) tokenCode(clientID string, form map[string]string) (map[string]any, error) {
	var out map[string]any
	var oerr *Error
	// Never fail inside the transaction: revocations must commit.
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketCodes)
		hash := sha256Hex(form["code"])
		data := b.Get([]byte(hash))
		if data == nil {
			oerr = oauthError("invalid_grant", "unknown code", 400)
			return nil
		}
		var r authCode
		if err := json.Unmarshal(data, &r); err != nil {
			return err
		}
		if r.Used {
			if err := revokeFamily(tx, r.Family, ""); err != nil {
				return err
			}
			oerr = oauthError("invalid_grant", "code already used", 400)
			return nil
		}
		r.Used = true
		if err := putJSON(b, []byte(hash), r); err != nil {
			return err
		}
		verifier := form["code_verifier"]
		sum := sha256.Sum256([]byte(verifier))
		challenge := base64.RawURLEncoding.EncodeToString(sum[:])
		switch {
		case r.ExpiresAt < s.now() || r.ClientID != clientID || r.RedirectURI != form["redirect_uri"]:
			oerr = oauthError("invalid_grant", "code expired or client/redirect mismatch", 400)
		case !verifierPattern.MatchString(verifier) || subtle.ConstantTimeCompare([]byte(challenge), []byte(r.Challenge)) != 1:
			oerr = oauthError("invalid_grant", "PKCE verification failed", 400)
		case form["resource"] != "" && form["resource"] != r.Resource:
			oerr = oauthError("invalid_target", "resource mismatch", 400)
		default:
			res, err := s.issue(tx, clientID, r.Scope, r.Resource, r.Family)
			if err != nil {
				return err
			}
			out = res
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if oerr != nil {
		return nil, oerr
	}
	return out, nil
}

func (s *Server) tokenRefresh(clientID string, form map[string]string) (map[string]any, error) {
	var out map[string]any
	var oerr *Error
	err := s.db.Update(func(tx *bolt.Tx) error {
		r, err := loadToken(tx, form["refresh_token"], "refresh")
		if err != nil {
			return err
		}
		if r == nil || r.Revoked || r.ExpiresAt < s.now() || r.ClientID != clientID {
			oerr = oauthError("invalid_grant", "refresh token invalid", 400)
			return nil
		}
		hash := sha256Hex(form["refresh_token"])
		if r.Used { // replay: revoke the whole chain
			if err := revokeFamily(tx, r.Family, ""); err != nil {
				return err
			}
			oerr = oauthError("invalid_grant", "refresh token already used", 400)
			return nil
		}
		if form["resource"] != "" && form["resource"] != r.Resource {
			oerr = oauthError("invalid_target", "resource mismatch", 400)
			return nil
		}
		scope := r.Scope
		if req := form["scope"]; req != "" {
			granted := map[string]bool{}
			for _, g := range strings.Fields(scope) {
				granted[g] = true
			}
			reqScopes := strings.Fields(req)
			for _, rs := range reqScopes {
				if !granted[rs] {
					oerr = oauthError("invalid_scope", "cannot widen scope", 400)
					return nil
				}
			}
			scope = strings.Join(reqScopes, " ")
		}
		r.Used = true
		if err := putJSON(tx.Bucket(bucketTokens), []byte(hash), *r); err != nil {
			return err
		}
		if err := revokeFamily(tx, r.Family, "access"); err != nil {
			return err
		}
		res, err := s.issue(tx, clientID, scope, r.Resource, r.Family)
		if err != nil {
			return err
		}
		out = res
		return nil
	})
	if err != nil {
		return nil, err
	}
	if oerr != nil {
		return nil, oerr
	}
	return out, nil
}

// Identity is what an access token proves at the MCP endpoint.
type Identity struct {
	Principal string
	Scopes    []string
	Family    string
	Peer      string // hub peer the token acts as
}

// VerifyAccess validates an access token for this resource.
func (s *Server) VerifyAccess(raw string) *Identity {
	if raw == "" || len(raw) > 200 {
		return nil
	}
	var id *Identity
	_ = s.db.View(func(tx *bolt.Tx) error {
		t, err := loadToken(tx, raw, "access")
		if err != nil || t == nil {
			return err
		}
		if t.Revoked || t.Used || t.ExpiresAt < s.now() || t.Resource != s.resource {
			return nil
		}
		id = &Identity{Principal: s.cfg.Peer, Scopes: strings.Fields(t.Scope), Family: t.Family, Peer: s.cfg.Peer}
		return nil
	})
	return id
}

// RevokeAll revokes every token and drops codes, pending requests and known
// devices (the `relaynote admin` unlock path).
func (s *Server) RevokeAll() (int, error) {
	n := 0
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketTokens)
		err := b.ForEach(func(k, v []byte) error {
			var t token
			if err := json.Unmarshal(v, &t); err != nil {
				return err
			}
			if !t.Revoked {
				t.Revoked = true
				n++
				return putJSON(b, append([]byte{}, k...), t)
			}
			return nil
		})
		if err != nil {
			return err
		}
		for _, name := range [][]byte{bucketCodes, bucketRequests, bucketDevices} {
			if err := tx.DeleteBucket(name); err != nil && !errors.Is(err, bolt.ErrBucketNotFound) {
				return err
			}
			if _, err := tx.CreateBucket(name); err != nil {
				return err
			}
		}
		return nil
	})
	return n, err
}

// ------------------------------------------------------------------ helpers

func randomString(size int) (string, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func randomHex(size int) (string, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func putJSON(b *bolt.Bucket, key []byte, value any) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return b.Put(key, encoded)
}
