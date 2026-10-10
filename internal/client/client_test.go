package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testToken = "synthetic-test-token"

func newTestClient(t *testing.T, cfg Config) *Client {
	t.Helper()
	if cfg.Token == "" {
		cfg.Token = testToken
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.http.CloseIdleConnections)
	return c
}

func caFile(t *testing.T, server *httptest.Server) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "synthetic-ca.pem")
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func tlsServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	s := httptest.NewUnstartedServer(handler)
	// Failed TLS validation is expected in negative cases; keep test output
	// quiet and do not turn peer error strings into application logs.
	s.Config.ErrorLog = log.New(io.Discard, "", 0)
	s.StartTLS()
	t.Cleanup(s.Close)
	return s
}

func TestLoopbackJSONRoundTrip(t *testing.T) {
	type message struct {
		Text string `json:"text"`
	}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/messages" || r.URL.RawQuery != "" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer "+testToken {
			t.Error("Bearer header missing or incorrect")
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type = %q", got)
		}
		if got := r.Header.Get("Accept"); got != "application/json" {
			t.Errorf("Accept = %q", got)
		}
		if r.ContentLength <= 0 {
			t.Error("JSON request must have a known content length")
		}
		var got message
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Error(err)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(got)
	}))
	defer s.Close()
	c := newTestClient(t, Config{BaseURL: s.URL + "/"})
	want := message{Text: "synthetic message: 你好"}
	var got message
	if err := c.Do(context.Background(), http.MethodPost, "/v1/messages", want, &got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestTransportDefaults(t *testing.T) {
	c := newTestClient(t, Config{BaseURL: "https://relay.example.invalid"})
	if c.http.Timeout != 15*time.Second {
		t.Errorf("timeout = %v", c.http.Timeout)
	}
	tr := c.http.Transport.(*http.Transport)
	if tr.Proxy != nil {
		t.Error("environment proxies must be disabled by default")
	}
	if tr.TLSClientConfig.InsecureSkipVerify || tr.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		t.Error("TLS verification or minimum TLS version is unsafe")
	}
	if tr.TLSClientConfig.RootCAs != nil {
		t.Error("default TLS should use platform trust roots")
	}
	custom := newTestClient(t, Config{BaseURL: "https://relay.example.invalid", Timeout: 123 * time.Millisecond})
	if custom.http.Timeout != 123*time.Millisecond {
		t.Error("configured timeout was not retained")
	}
}

func TestTLSVerificationAndAdditionalCA(t *testing.T) {
	var hits atomic.Int32
	s := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("Authorization") != "Bearer "+testToken {
			t.Error("missing authorization over TLS")
		}
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))

	t.Run("unknown CA rejected", func(t *testing.T) {
		c := newTestClient(t, Config{BaseURL: s.URL})
		var result any
		err := c.Do(context.Background(), http.MethodGet, "/v1/messages", nil, &result)
		var unknownCA x509.UnknownAuthorityError
		if !errors.As(err, &unknownCA) {
			t.Fatalf("wanted discoverable unknown CA error, got %v", err)
		}
		if hits.Load() != 0 {
			t.Error("request reached the handler before certificate validation")
		}
	})

	certPath := caFile(t, s)
	t.Run("additional CA trusted", func(t *testing.T) {
		c := newTestClient(t, Config{BaseURL: s.URL, CAFile: certPath})
		var result struct {
			OK bool `json:"ok"`
		}
		if err := c.Do(context.Background(), http.MethodGet, "/v1/messages", nil, &result); err != nil {
			t.Fatal(err)
		}
		if !result.OK || hits.Load() != 1 {
			t.Fatal("trusted TLS request did not complete")
		}
	})

	t.Run("hostname still verified", func(t *testing.T) {
		c := newTestClient(t, Config{BaseURL: "https://wrong.example.invalid", CAFile: certPath})
		// Route the synthetic name straight to the local test listener. This
		// exercises hostname verification without public DNS or endpoints.
		c.http.Transport.(*http.Transport).DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, s.Listener.Addr().String())
		}
		err := c.Do(context.Background(), http.MethodGet, "/v1/messages", nil, nil)
		var hostname x509.HostnameError
		if !errors.As(err, &hostname) {
			t.Fatalf("wanted hostname validation failure, got %v", err)
		}
		if hits.Load() != 1 {
			t.Error("hostname-invalid request reached the handler")
		}
	})
}

func TestInvalidConfig(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
	}{
		{"empty origin", Config{Token: testToken}},
		{"relative origin", Config{BaseURL: "/v1/", Token: testToken}},
		{"remote plaintext", Config{BaseURL: "http://relay.example.invalid", Token: testToken}},
		{"localhost is not literal", Config{BaseURL: "http://localhost", Token: testToken}},
		{"private plaintext", Config{BaseURL: "http://192.168.0.1", Token: testToken}},
		{"lookalike loopback", Config{BaseURL: "http://127.0.0.1.example.invalid", Token: testToken}},
		{"short IPv4 form", Config{BaseURL: "http://127.1", Token: testToken}},
		{"integer IPv4 form", Config{BaseURL: "http://2130706433", Token: testToken}},
		{"IPv6 remote plaintext", Config{BaseURL: "http://[2001:db8::1]", Token: testToken}},
		{"unsupported scheme", Config{BaseURL: "ftp://relay.example.invalid", Token: testToken}},
		{"missing host", Config{BaseURL: "https:///", Token: testToken}},
		{"userinfo", Config{BaseURL: "https://secret:password@relay.example.invalid", Token: testToken}},
		{"empty userinfo", Config{BaseURL: "https://@relay.example.invalid", Token: testToken}},
		{"query", Config{BaseURL: "https://relay.example.invalid?secret=value", Token: testToken}},
		{"empty query", Config{BaseURL: "https://relay.example.invalid?", Token: testToken}},
		{"fragment", Config{BaseURL: "https://relay.example.invalid#secret", Token: testToken}},
		{"empty fragment", Config{BaseURL: "https://relay.example.invalid#", Token: testToken}},
		{"base path", Config{BaseURL: "https://relay.example.invalid/api", Token: testToken}},
		{"encoded base path", Config{BaseURL: "https://relay.example.invalid/%2e", Token: testToken}},
		{"encoded base root", Config{BaseURL: "https://relay.example.invalid/%2f", Token: testToken}},
		{"bad port", Config{BaseURL: "https://relay.example.invalid:bad", Token: testToken}},
		{"empty port", Config{BaseURL: "https://relay.example.invalid:", Token: testToken}},
		{"large port", Config{BaseURL: "https://relay.example.invalid:65536", Token: testToken}},
		{"zero port", Config{BaseURL: "https://relay.example.invalid:0", Token: testToken}},
		{"unbracketed IPv6", Config{BaseURL: "https://::1", Token: testToken}},
		{"empty token", Config{BaseURL: "https://relay.example.invalid"}},
		{"space in token", Config{BaseURL: "https://relay.example.invalid", Token: "secret token"}},
		{"newline in token", Config{BaseURL: "https://relay.example.invalid", Token: "secret\r\nInjected: value"}},
		{"non-ASCII token", Config{BaseURL: "https://relay.example.invalid", Token: "secret你好"}},
		{"negative timeout", Config{BaseURL: "https://relay.example.invalid", Token: testToken, Timeout: -time.Second}},
		{"missing CA", Config{BaseURL: "https://relay.example.invalid", Token: testToken, CAFile: filepath.Join(t.TempDir(), "absent.pem")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.cfg); err == nil {
				t.Fatal("invalid config accepted")
			} else if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), testToken) {
				t.Fatal("configuration error disclosed supplied secret")
			}
		})
	}

	for _, origin := range []string{"http://127.0.0.1", "http://127.5.6.7:8080", "http://[::1]:8080", "http://[::ffff:127.0.0.1]:8080", "https://relay.example.invalid/"} {
		t.Run("allowed "+origin, func(t *testing.T) {
			newTestClient(t, Config{BaseURL: origin})
		})
	}
	badCA := filepath.Join(t.TempDir(), "not-a-certificate.pem")
	if err := os.WriteFile(badCA, []byte("not a certificate"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{BaseURL: "https://relay.example.invalid", Token: testToken, CAFile: badCA}); err == nil {
		t.Error("invalid PEM accepted")
	}
}

func TestUnsafeRoutesRejectedBeforeNetwork(t *testing.T) {
	var hits atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, `{}`)
	}))
	defer s.Close()
	c := newTestClient(t, Config{BaseURL: s.URL})
	paths := []string{
		"", "/", "/v1", "v1/messages", "https://other.example.invalid/v1/messages",
		"//other.example.invalid/v1/messages", "/v1evil/messages", "/v1/../admin",
		"/v1/./messages", "/v1/messages/..", "/v1//messages", "/v1/%2e%2e/admin",
		"/v1/%252e%252e/admin", "/v1/a%2fb", "/v1/a%5cb", "/v1/messages?token=secret",
		"/v1/messages?", "/v1/messages#secret", "/v1/messages#", "/v1/\\other",
		"/v1/secret\r\nHeader:value", "/v1/some path", "/v1/你好", "/v1/\x00",
	}
	for _, path := range paths {
		if err := c.Do(context.Background(), http.MethodGet, path, nil, nil); err == nil {
			t.Errorf("unsafe path accepted: %q", path)
		}
	}
	if hits.Load() != 0 {
		t.Errorf("%d unsafe paths reached server", hits.Load())
	}
}

func TestRedirectsNeverFollowed(t *testing.T) {
	var targetHits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits.Add(1)
		_, _ = io.WriteString(w, `{}`)
	}))
	defer target.Close()
	var sameOriginHits atomic.Int32
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/redirect-target" {
			sameOriginHits.Add(1)
			_, _ = io.WriteString(w, `{}`)
			return
		}
		location := target.URL + "/v1/redirect-target"
		if strings.HasSuffix(r.URL.Path, "same-origin") {
			location = "/v1/redirect-target"
		}
		w.Header().Set("Location", location)
		w.WriteHeader(http.StatusTemporaryRedirect)
		_, _ = io.WriteString(w, "secret response body")
	}))
	defer source.Close()
	c := newTestClient(t, Config{BaseURL: source.URL})
	for _, route := range []string{"/v1/other-origin", "/v1/same-origin"} {
		err := c.Do(context.Background(), http.MethodPost, route, map[string]string{"secret": "request body"}, nil)
		var httpErr *HTTPError
		if !errors.As(err, &httpErr) || httpErr.Status != http.StatusTemporaryRedirect {
			t.Fatalf("redirect did not return HTTPError: %v", err)
		}
		if strings.Contains(err.Error(), "secret") {
			t.Fatal("redirect body leaked")
		}
	}
	if targetHits.Load() != 0 || sameOriginHits.Load() != 0 {
		t.Fatal("a redirect target was contacted")
	}
}

func TestHTTPErrorDoesNotExposeServerBody(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusInternalServerError, 599} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(status)
				_, _ = io.WriteString(w, `{"error":"`+testToken+` private message body"}`)
			}))
			defer s.Close()
			c := newTestClient(t, Config{BaseURL: s.URL})
			var result map[string]any
			err := c.Do(context.Background(), http.MethodGet, "/v1/messages", nil, &result)
			var httpErr *HTTPError
			if !errors.As(err, &httpErr) || httpErr.Status != status || httpErr.Message == "" {
				t.Fatalf("unexpected error: %v", err)
			}
			if strings.Contains(err.Error(), testToken) || strings.Contains(err.Error(), "private") || result != nil {
				t.Fatal("HTTP error exposed server content")
			}
		})
	}
}

func TestResponseDecoding(t *testing.T) {
	for _, tc := range []struct {
		name    string
		body    string
		out     bool
		wantErr string
	}{
		{"valid", `{"ok":true}`, true, ""},
		{"malformed", `{"secret":`, true, "decoded as JSON"},
		{"multiple JSON values", `{} {}`, true, "decoded as JSON"},
		{"empty with output", "", true, "decoded as JSON"},
		{"empty without output", "", false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.WriteString(w, tc.body)
			}))
			defer s.Close()
			c := newTestClient(t, Config{BaseURL: s.URL})
			var result any
			var out any
			if tc.out {
				out = &result
			}
			err := c.Do(context.Background(), http.MethodGet, "/v1/messages", nil, out)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("wanted error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestResponseLimit(t *testing.T) {
	if maxResponseBytes != 48<<20 {
		t.Fatal("response limit must accommodate the full protocol claim size")
	}
	for _, tc := range []struct {
		name string
		size int
		out  bool
	}{
		{"exact limit", maxResponseBytes, true},
		{"over limit", maxResponseBytes + 1, true},
		{"over limit without output", maxResponseBytes + 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Stream rather than retaining another 48 MiB response in the
				// test process. Each response is one valid JSON string.
				_, _ = io.WriteString(w, `"`)
				chunk := strings.Repeat("a", 32<<10)
				for remaining := tc.size - 2; remaining > 0; {
					n := min(remaining, len(chunk))
					if _, err := io.WriteString(w, chunk[:n]); err != nil {
						return
					}
					remaining -= n
				}
				_, _ = io.WriteString(w, `"`)
			}))
			defer s.Close()
			c := newTestClient(t, Config{BaseURL: s.URL})
			var result string
			var out any
			if tc.out {
				out = &result
			}
			err := c.Do(context.Background(), http.MethodGet, "/v1/messages", nil, out)
			if tc.size <= maxResponseBytes {
				if err != nil || len(result) != tc.size-2 {
					t.Fatalf("valid boundary response failed: %v, decoded length %d", err, len(result))
				}
			} else if err == nil || !strings.Contains(err.Error(), "48 MiB") {
				t.Fatalf("oversized response was not rejected: %v", err)
			}
		})
	}
}

func TestMaximumEscapedClaimResponse(t *testing.T) {
	type message struct {
		Body string `json:"body"`
	}
	const messageCount = 100
	// One NUL occupies a byte in the protocol body and six bytes in JSON.
	// This models the maximum escaping overhead of a full 100-message claim.
	wantBody := strings.Repeat("\x00", 64<<10)
	encoded, err := json.Marshal(message{Body: wantBody})
	if err != nil {
		t.Fatal(err)
	}
	wireBytes := len(`{"messages":[`) + messageCount*len(encoded) + messageCount - 1 + len(`]}`)
	if wireBytes <= 1<<20 || wireBytes > maxResponseBytes {
		t.Fatalf("unexpected maximum claim size: %d bytes", wireBytes)
	}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"messages":[`)
		for i := 0; i < messageCount; i++ {
			if i != 0 {
				_, _ = io.WriteString(w, ",")
			}
			if _, err := w.Write(encoded); err != nil {
				return
			}
		}
		_, _ = io.WriteString(w, `]}`)
	}))
	defer s.Close()
	c := newTestClient(t, Config{BaseURL: s.URL})
	var result struct {
		Messages []message `json:"messages"`
	}
	if err := c.Do(context.Background(), http.MethodPost, "/v1/inbox/claim", map[string]int{"limit": messageCount}, &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Messages) != messageCount {
		t.Fatalf("claim contained %d messages, want %d", len(result.Messages), messageCount)
	}
	for i, msg := range result.Messages {
		if msg.Body != wantBody {
			t.Fatalf("message %d was not decoded intact", i)
		}
	}
}

func TestContextCancellationAndTimeout(t *testing.T) {
	arrived := make(chan struct{}, 4)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		arrived <- struct{}{}
		<-r.Context().Done()
	}))
	defer s.Close()

	t.Run("in-flight cancel", func(t *testing.T) {
		c := newTestClient(t, Config{BaseURL: s.URL})
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- c.Do(ctx, http.MethodGet, "/v1/messages", nil, nil) }()
		select {
		case <-arrived:
		case <-time.After(5 * time.Second):
			t.Fatal("request did not reach server")
		}
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation not preserved: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("request ignored context cancellation")
		}
	})

	t.Run("client timeout", func(t *testing.T) {
		c := newTestClient(t, Config{BaseURL: s.URL, Timeout: 50 * time.Millisecond})
		err := c.Do(context.Background(), http.MethodGet, "/v1/messages", nil, nil)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("timeout not preserved: %v", err)
		}
	})

	t.Run("already canceled", func(t *testing.T) {
		c := newTestClient(t, Config{BaseURL: s.URL})
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := c.Do(ctx, http.MethodGet, "/v1/messages", nil, nil); !errors.Is(err, context.Canceled) {
			t.Fatalf("preexisting cancellation not preserved: %v", err)
		}
	})
}

func TestPlainHTTPRejectsAllProxyModes(t *testing.T) {
	var proxyHits atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyHits.Add(1)
	}))
	defer proxy.Close()
	for _, base := range []string{"http://127.0.0.1:45678", "http://[::1]:45678"} {
		for _, cfg := range []Config{
			{BaseURL: base, Token: testToken, ProxyURL: proxy.URL},
			{BaseURL: base, Token: testToken, ProxyURL: "http://proxy.example.invalid:8080"},
			{BaseURL: base, Token: testToken, ProxyURL: "https://proxy.example.invalid:8080"},
			{BaseURL: base, Token: testToken, UseEnvProxy: true},
		} {
			if _, err := New(cfg); err == nil || !strings.Contains(err.Error(), "proxies require an HTTPS base URL") {
				t.Fatalf("plaintext proxy configuration was not rejected: %v", err)
			}
		}
	}
	if proxyHits.Load() != 0 {
		t.Fatal("a plaintext origin contacted a proxy")
	}
}

func TestExplicitProxyCONNECT(t *testing.T) {
	origin := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testToken {
			t.Error("missing tunneled authorization")
		}
		_, _ = io.WriteString(w, `{"secure":true}`)
	}))
	originURL, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	var connectHits atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || r.Host != originURL.Host {
			t.Errorf("unexpected CONNECT: %s %s", r.Method, r.Host)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		connectHits.Add(1)
		if r.Header.Get("Authorization") != "" || r.Header.Get("Proxy-Authorization") != "" {
			t.Error("CONNECT exposed an authentication header")
		}
		upstream, err := net.Dial("tcp", origin.Listener.Addr().String())
		if err != nil {
			t.Error(err)
			http.Error(w, "unavailable", http.StatusBadGateway)
			return
		}
		defer upstream.Close()
		downstream, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer downstream.Close()
		_, _ = rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		if err := rw.Flush(); err != nil {
			return
		}
		done := make(chan struct{})
		go func() {
			_, _ = io.Copy(upstream, rw)
			_ = upstream.Close()
			close(done)
		}()
		_, _ = io.Copy(downstream, upstream)
		_ = downstream.Close()
		<-done
	}))
	defer proxy.Close()
	c := newTestClient(t, Config{BaseURL: origin.URL, CAFile: caFile(t, origin), ProxyURL: proxy.URL})
	var result struct {
		Secure bool `json:"secure"`
	}
	if err := c.Do(context.Background(), http.MethodGet, "/v1/messages", nil, &result); err != nil {
		t.Fatal(err)
	}
	if !result.Secure || connectHits.Load() != 1 {
		t.Fatal("HTTPS request did not use the proxy tunnel")
	}
}

func TestInvalidProxyConfig(t *testing.T) {
	for _, proxy := range []string{
		"socks5://127.0.0.1:8080", "//127.0.0.1:8080", "http://secret:password@127.0.0.1:8080",
		"http://@127.0.0.1:8080", "http://127.0.0.1:8080/path", "http://127.0.0.1:8080?secret",
		"http://127.0.0.1:8080#secret", "http://127.0.0.1:0", "http://127.0.0.1:",
	} {
		if _, err := New(Config{BaseURL: "https://relay.example.invalid", Token: testToken, ProxyURL: proxy}); err == nil {
			t.Errorf("invalid proxy accepted: %s", proxy)
		} else if strings.Contains(err.Error(), "secret") {
			t.Error("invalid proxy error disclosed credentials")
		}
	}
	if _, err := New(Config{BaseURL: "https://relay.example.invalid", Token: testToken, ProxyURL: "http://127.0.0.1:8080", UseEnvProxy: true}); err == nil {
		t.Fatal("ambiguous proxy policy accepted")
	}
	newTestClient(t, Config{BaseURL: "https://relay.example.invalid", ProxyURL: "https://127.0.0.1:8080"})
}

func TestEnvironmentProxyOptIn(t *testing.T) {
	// net/http caches proxy environment discovery process-wide. A subprocess
	// gives this assertion a deterministic, isolated environment on every OS.
	cmd := exec.Command(os.Args[0], "-test.run=^TestEnvironmentProxyHelper$")
	keys := map[string]bool{
		"HTTP_PROXY": true, "HTTPS_PROXY": true, "ALL_PROXY": true, "NO_PROXY": true,
		"REQUEST_METHOD": true, "RELAYNOTE_PROXY_HELPER": true,
	}
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if !keys[strings.ToUpper(key)] {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	cmd.Env = append(cmd.Env,
		"RELAYNOTE_PROXY_HELPER=1",
		"HTTP_PROXY=http://127.0.0.1:45679",
		"HTTPS_PROXY=http://127.0.0.1:45679",
		"NO_PROXY=",
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("proxy helper failed: %v\n%s", err, output)
	}
}

func TestEnvironmentProxyHelper(t *testing.T) {
	if os.Getenv("RELAYNOTE_PROXY_HELPER") != "1" {
		t.Skip("run only in the isolated helper process")
	}
	for _, useEnv := range []bool{false, true} {
		c := newTestClient(t, Config{BaseURL: "https://relay.example.invalid", UseEnvProxy: useEnv})
		proxyFunc := c.http.Transport.(*http.Transport).Proxy
		if !useEnv {
			if proxyFunc != nil {
				t.Fatal("proxy environment used without opt-in")
			}
			continue
		}
		if proxyFunc == nil {
			t.Fatal("proxy environment opt-in was ignored")
		}
		req, err := http.NewRequest(http.MethodGet, "https://relay.example.invalid/v1/messages", nil)
		if err != nil {
			t.Fatal(err)
		}
		proxyURL, err := proxyFunc(req)
		if err != nil || proxyURL == nil || proxyURL.String() != "http://127.0.0.1:45679" {
			t.Fatalf("environment proxy not selected: %v, %v", proxyURL, err)
		}
		// This is discovery only. It deliberately makes no network request.
	}
}

func TestBadInputsDoNotReachNetwork(t *testing.T) {
	c := newTestClient(t, Config{BaseURL: "http://127.0.0.1:45678"})
	if err := c.Do(nil, http.MethodGet, "/v1/messages", nil, nil); err == nil {
		t.Error("nil context accepted")
	}
	if err := c.Do(context.Background(), "INVALID METHOD", "/v1/messages", nil, nil); err == nil || !strings.Contains(err.Error(), "invalid HTTP request") {
		t.Errorf("invalid method handling: %v", err)
	}
	if err := c.Do(context.Background(), http.MethodPost, "/v1/messages", make(chan int), nil); err == nil || !strings.Contains(err.Error(), "encoded as JSON") {
		t.Errorf("unsupported body handling: %v", err)
	}
	var uninitialized Client
	if err := uninitialized.Do(context.Background(), http.MethodGet, "/v1/messages", nil, nil); err == nil {
		t.Error("uninitialized client accepted")
	}
	var absent *Client
	if err := absent.Do(context.Background(), http.MethodGet, "/v1/messages", nil, nil); err == nil {
		t.Error("nil client accepted")
	}
}
