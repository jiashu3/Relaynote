// Package client implements the shared Relaynote HTTPS protocol. Plain HTTP is
// accepted only for explicitly configured literal loopback addresses in tests.
package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultTimeout = 15 * time.Second
	// A claim may contain 100 messages of 64 KiB each. JSON can expand each
	// body byte to six bytes (for example, a NUL becomes \u0000).
	maxResponseBytes = 48 << 20
)

// Config describes a single server and its transport. Proxy use is always
// explicit and requires an HTTPS server: either ProxyURL or UseEnvProxy must
// be set to enable it. Loopback HTTP connections are always direct.
type Config struct {
	BaseURL     string
	Token       string
	CAFile      string
	ProxyURL    string
	UseEnvProxy bool
	Timeout     time.Duration
}

// Client is safe for concurrent requests. Its server, credentials, and transport
// are fixed at construction time.
type Client struct {
	baseURL *url.URL
	token   string
	http    *http.Client
}

// HTTPError reports an unsuccessful HTTP status. Message is a local status
// description, never a server-supplied response body or credential.
type HTTPError struct {
	Status  int
	Message string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("relaynote: HTTP %d: %s", e.Status, e.Message)
}

// New constructs a client with normal TLS certificate and hostname validation.
// CAFile, when set, adds PEM trust roots to the operating system's roots.
func New(cfg Config) (*Client, error) {
	base, err := endpointURL(cfg.BaseURL)
	if err != nil {
		return nil, errors.New("relaynote: invalid base URL; use an HTTPS origin or literal loopback HTTP origin")
	}
	if base.Scheme == "http" {
		ip := net.ParseIP(base.Hostname())
		if ip == nil || !ip.IsLoopback() {
			return nil, errors.New("relaynote: plain HTTP requires a literal loopback IP address")
		}
		if cfg.ProxyURL != "" || cfg.UseEnvProxy {
			return nil, errors.New("relaynote: proxies require an HTTPS base URL")
		}
	}
	if !validToken(cfg.Token) {
		return nil, errors.New("relaynote: a nonempty Bearer token without spaces or control characters is required")
	}
	if cfg.Timeout < 0 {
		return nil, errors.New("relaynote: timeout must not be negative")
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = defaultTimeout
	}
	if cfg.ProxyURL != "" && cfg.UseEnvProxy {
		return nil, errors.New("relaynote: choose either an explicit proxy or environment proxy discovery")
	}

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.CAFile != "" {
		pemData, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, errors.New("relaynote: could not read CA file")
		}
		roots, err := x509.SystemCertPool()
		if err != nil {
			return nil, errors.New("relaynote: could not load system trust roots")
		}
		if roots == nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(pemData) {
			return nil, errors.New("relaynote: CA file contains no usable PEM certificates")
		}
		tlsConfig.RootCAs = roots
	}

	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:      true,
		TLSClientConfig:        tlsConfig,
		TLSHandshakeTimeout:    10 * time.Second,
		IdleConnTimeout:        90 * time.Second,
		MaxIdleConns:           20,
		MaxIdleConnsPerHost:    10,
		ExpectContinueTimeout:  time.Second,
		MaxResponseHeaderBytes: 64 << 10,
	}
	if cfg.ProxyURL != "" {
		proxy, err := endpointURL(cfg.ProxyURL)
		if err != nil {
			return nil, errors.New("relaynote: invalid proxy URL; use an HTTP or HTTPS origin without credentials")
		}
		transport.Proxy = http.ProxyURL(proxy)
	} else if cfg.UseEnvProxy {
		transport.Proxy = http.ProxyFromEnvironment
	}

	return &Client{
		baseURL: base,
		token:   cfg.Token,
		http: &http.Client{
			Transport: transport,
			Timeout:   cfg.Timeout,
			// Do not forward authentication to a Location target, even if it
			// appears to share this server's origin.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

// Do calls a canonical /v1/ route at the configured origin. A non-nil body is
// JSON-encoded. If out is non-nil, a successful nonempty response is decoded into
// it. Empty successful responses (for example 204) are accepted when out is nil.
// Error response bodies are never returned to the caller.
func (c *Client) Do(ctx context.Context, method, path string, body any, out any) error {
	if c == nil || c.baseURL == nil || c.http == nil {
		return errors.New("relaynote: client is not initialized")
	}
	if ctx == nil {
		return errors.New("relaynote: context is required")
	}
	if !validRoute(path) {
		return errors.New("relaynote: route must be a canonical /v1/ path without query, fragment, or traversal")
	}
	var payload io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return errors.New("relaynote: request body cannot be encoded as JSON")
		}
		payload = bytes.NewReader(data)
	}
	// Copy instead of resolving a reference: the caller cannot replace the
	// configured scheme, host, or port.
	u := *c.baseURL
	u.Path = path
	u.RawPath = ""
	req, err := http.NewRequestWithContext(ctx, method, u.String(), payload)
	if err != nil {
		return errors.New("relaynote: invalid HTTP request")
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		// Keep context and certificate errors discoverable without including
		// potentially sensitive server/proxy text in the error string.
		return &requestError{cause: err}
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		message := http.StatusText(resp.StatusCode)
		if message == "" {
			message = "unsuccessful response"
		}
		return &HTTPError{Status: resp.StatusCode, Message: message}
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return &requestError{cause: err}
	}
	if len(data) > maxResponseBytes {
		return errors.New("relaynote: response exceeds 48 MiB limit")
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return errors.New("relaynote: response could not be decoded as JSON")
		}
	}
	return nil
}

// requestError preserves errors.Is/As (including cancellation and TLS errors)
// without incorporating an untrusted transport error in user-facing text.
type requestError struct {
	cause error
}

func (e *requestError) Error() string { return "relaynote: HTTP request failed" }
func (e *requestError) Unwrap() error { return e.cause }

func endpointURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.Hostname() == "" ||
		u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.ForceQuery ||
		u.Fragment != "" || strings.Contains(raw, "#") ||
		(u.Path != "" && u.Path != "/") || u.RawPath != "" {
		return nil, errors.New("invalid origin")
	}
	// url.Parse permits some unusable port/address combinations. Reject them
	// at configuration time, before an authenticated request can be built.
	if strings.HasSuffix(u.Host, ":") {
		return nil, errors.New("empty port")
	}
	if strings.Contains(u.Hostname(), ":") {
		if !strings.HasPrefix(u.Host, "[") || net.ParseIP(u.Hostname()) == nil {
			return nil, errors.New("invalid IP literal")
		}
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return nil, errors.New("invalid port")
		}
	}
	u.Path = ""
	return u, nil
}

func validToken(token string) bool {
	if token == "" {
		return false
	}
	for _, r := range token {
		if r < 33 || r > 126 {
			return false
		}
	}
	return true
}

func validRoute(path string) bool {
	if !strings.HasPrefix(path, "/v1/") || strings.Contains(path, "//") {
		return false
	}
	for _, r := range path {
		// Protocol routes use literal, printable ASCII. Reject escapes too so
		// intermediaries cannot introduce a second decoding of separators or
		// dot segments. IDs supplied by the protocol need no URL escaping.
		if r < 33 || r > 126 || strings.ContainsRune("%\\?#", r) {
			return false
		}
	}
	for _, part := range strings.Split(path, "/") {
		if part == "." || part == ".." {
			return false
		}
	}
	return true
}
