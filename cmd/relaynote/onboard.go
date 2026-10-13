// P3 onboarding: hub init, connect --platform, doctor. All local operations:
// init/connect/doctor open the hub database directly (stop the hub first, as
// with provision/manage), and doctor's only network calls are the peer's own
// adapter dry-run and the optional live wake-status query.
package main

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"relaynote/internal/client"
	"relaynote/internal/store"
	"relaynote/internal/wake"
	"strings"
	"text/template"
	"time"
)

//go:embed snippets/*.tmpl
var snippetFS embed.FS

var snippetTemplates = template.Must(template.ParseFS(snippetFS, "snippets/*.tmpl"))

// platformAlias maps user-facing platform names to wake adapters.
var platformAlias = map[string]string{
	"mcp": "mcp", "chatgpt": "mcp", "dot": "mcp",
	"webhook": "webhook", "cursor": "webhook", "grokbot": "webhook",
	"exec": "exec", "codex": "exec", "claude-code": "exec",
	"poll": "poll", "generic-poll": "poll", "cue": "poll",
	"none": "none",
}

// defaultWakeConfigPath keeps the wake config next to the hub database.
func defaultWakeConfigPath(dbPath string) string {
	return filepath.Join(filepath.Dir(dbPath), "wake.json")
}

// hubURLFilePath keeps the URL recorded by hub init --url next to hub.db.
func hubURLFilePath(dbPath string) string {
	return filepath.Join(filepath.Dir(dbPath), "hub.url")
}

// recordedHubURL reads the hub URL saved by hub init --url, if any.
func recordedHubURL(dbPath string) string {
	data, err := os.ReadFile(hubURLFilePath(dbPath))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// hubInit creates a fresh hub database with one admin peer. The admin token
// is printed once; only its SHA-256 hash is stored. An existing hub.db is
// never overwritten.
func hubInit(args []string, out io.Writer) error {
	f := flags("hub init")
	dir := f.String("dir", "hub", "hub state directory (created private, mode 0700)")
	hubURL := f.String("url", "", "public/listen hub URL recorded to hub.url; later connect/doctor runs use it as a default")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return errors.New("unexpected arguments")
	}
	dbPath := filepath.Join(*dir, "hub.db")
	if _, err := os.Lstat(dbPath); err == nil {
		return fmt.Errorf("hub database already exists at %s; refusing to overwrite", dbPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect hub database: %w", err)
	}
	if err := os.MkdirAll(*dir, 0700); err != nil {
		return err
	}
	if err := os.Chmod(*dir, 0700); err != nil {
		return err
	}
	token, err := store.NewToken()
	if err != nil {
		return err
	}
	s, err := store.New(dbPath)
	if err != nil {
		return err
	}
	defer s.Close()
	if err := s.Provision("admin", []string{"*"}, token); err != nil {
		return err
	}
	urlLine := ""
	if u := strings.TrimSpace(*hubURL); u != "" {
		if err := os.WriteFile(hubURLFilePath(dbPath), []byte(u+"\n"), 0600); err != nil {
			return fmt.Errorf("record hub URL: %w", err)
		}
		urlLine = "hub URL recorded (hub.url): " + u + "\n"
	}
	_, err = fmt.Fprintf(out, `hub database: %s
admin peer: admin (allowed: *)
admin token (shown once; only its SHA-256 hash is stored): %s
%sSave it now; it cannot be recovered or shown again.

Next steps:
  relaynote --db %s connect --peer NAME --platform mcp|webhook|exec|poll|none
  relaynote --db %s serve --listen 127.0.0.1:8787 --wake-config %s --longpoll
  relaynote --db %s doctor --peer NAME

TLS: loopback serving needs no certificate. Listening beyond loopback requires
  --allow-remote --tls-cert server.crt --tls-key server.key (TLS 1.2+).
`, dbPath, token, urlLine, dbPath, dbPath, defaultWakeConfigPath(dbPath), dbPath)
	return err
}

// snippetData fills the embedded per-platform paste templates.
type snippetData struct {
	Peer       string
	Base       string
	DB         string
	WakeConfig string
	Token      string
	TokenFile  string
	WebhookURL string
	WebhookKey string
	ExecCmd    string
	Prompt     string
}

// renderPrompt renders the fixed agent prompt fragment. It is intentionally
// short: only the four verbs inbox/reply/send/status, well under 300 tokens.
func renderPrompt(d snippetData) (string, error) {
	var buf bytes.Buffer
	if err := snippetTemplates.ExecuteTemplate(&buf, "prompt.tmpl", d); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// loadWakeConfigForEdit reads a wake config for update; a missing file starts
// empty.
func loadWakeConfigForEdit(path string) (wake.Config, error) {
	cfg, err := wake.LoadConfig(path)
	if errors.Is(err, fs.ErrNotExist) {
		return wake.Config{Peers: map[string]wake.PeerConfig{}}, nil
	}
	if err != nil {
		return wake.Config{}, err
	}
	if cfg.Peers == nil {
		cfg.Peers = map[string]wake.PeerConfig{}
	}
	return cfg, nil
}

func saveWakeConfig(path string, cfg wake.Config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// connect creates a peer (token + ACL edges), records its wake adapter entry,
// and prints a paste-ready setup snippet for the chosen platform. baseSet is
// true when the global --url flag was passed explicitly.
func connect(args []string, dbPath, base string, baseSet bool, out io.Writer) error {
	f := flags("connect")
	peer := f.String("peer", "", "peer name to create")
	platform := f.String("platform", "", "mcp|webhook|exec|poll|none, or an alias: chatgpt, dot, cursor, grokbot, codex, claude-code, generic-poll, cue")
	allow := f.String("allow", "", "comma-separated ACL destinations; empty denies sends")
	hubURL := f.String("url", "", "hub URL used in snippets (default: global --url / RELAYNOTE_URL, then the URL recorded by hub init --url)")
	webhookURL := f.String("webhook-url", "", "wake callback URL (webhook platform)")
	execCmd := f.String("exec", "", "local command run on each wake notice (exec platform)")
	wakePath := f.String("wake-config", "", "wake config file (default: wake.json next to the database)")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return errors.New("unexpected arguments")
	}
	if *peer == "" {
		return errors.New("--peer required")
	}
	adapter, ok := platformAlias[*platform]
	if !ok {
		return fmt.Errorf("unknown --platform %q", *platform)
	}
	if *wakePath == "" {
		*wakePath = defaultWakeConfigPath(dbPath)
	}
	baseURL := strings.TrimSpace(*hubURL)
	if baseURL == "" && baseSet {
		baseURL = base
	}
	if baseURL == "" {
		baseURL = strings.TrimSpace(os.Getenv("RELAYNOTE_URL"))
	}
	if baseURL == "" {
		baseURL = recordedHubURL(dbPath)
	}
	if baseURL == "" {
		baseURL = defaultHubURL
	}
	acl := []string{}
	if *allow != "" {
		acl = strings.Split(*allow, ",")
	}
	d := snippetData{Peer: *peer, Base: strings.TrimRight(baseURL, "/"), DB: dbPath, WakeConfig: *wakePath}
	entry := wake.PeerConfig{}
	switch adapter {
	case "mcp":
		entry.Adapter = "mcp-event"
	case "webhook":
		if *webhookURL == "" {
			return errors.New("--webhook-url required for the webhook platform")
		}
		key, err := store.NewToken()
		if err != nil {
			return err
		}
		entry.Adapter, entry.WebhookURL, entry.HMACSecret = "webhook", *webhookURL, key
		d.WebhookURL, d.WebhookKey = *webhookURL, key
	case "exec":
		if *execCmd == "" {
			return errors.New("--exec required for the exec platform")
		}
		entry.Adapter, entry.ExecArgv = "exec", []string{*execCmd}
		d.ExecCmd = *execCmd
	case "poll":
		entry.Adapter = "poll"
	default: // none
		entry.Adapter = "none"
	}
	token, err := store.NewToken()
	if err != nil {
		return err
	}
	s, err := store.New(dbPath)
	if err != nil {
		return fmt.Errorf("open hub database (stop hub before local administration): %w", err)
	}
	err = s.Provision(*peer, acl, token)
	closeErr := s.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	d.Token = token
	d.TokenFile = filepath.Join(filepath.Dir(dbPath), *peer+".token")
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(d.TokenFile)
		}
	}()
	file, err := os.OpenFile(d.TokenFile, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err = file.WriteString(token + "\n"); err == nil {
		err = file.Sync()
	}
	if cerr := file.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	cfg, err := loadWakeConfigForEdit(*wakePath)
	if err != nil {
		return err
	}
	cfg.Peers[*peer] = entry
	if err := saveWakeConfig(*wakePath, cfg); err != nil {
		return err
	}
	committed = true
	if d.Prompt, err = renderPrompt(d); err != nil {
		return err
	}
	return snippetTemplates.ExecuteTemplate(out, adapter+".tmpl", d)
}

// doctorCheck is one OK/FAIL/SKIP line of a doctor report.
type doctorCheck struct {
	ok     bool // false prints FAIL; skipped checks are never failures
	skip   bool
	name   string
	detail string
}

// doctor verifies a peer end to end: token, ACL edges, adapter reachability,
// and the last recorded wake decision. It exits nonzero on any FAIL.
func doctor(args []string, dbPath, base, tokenFile string, timeout time.Duration, out io.Writer) error {
	f := flags("doctor")
	peer := f.String("peer", "", "peer to check")
	allow := f.String("allow", "", "comma-separated ACL edges that must exist")
	wakePath := f.String("wake-config", "", "wake config file (default: wake.json next to the database)")
	adapterTimeout := f.Duration("adapter-timeout", 3*time.Second, "timeout for adapter reachability checks")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return errors.New("unexpected arguments")
	}
	if *peer == "" {
		return errors.New("--peer required")
	}
	if *wakePath == "" {
		*wakePath = defaultWakeConfigPath(dbPath)
	}
	checks := []doctorCheck{}
	var info store.PeerInfo
	s, err := store.NewReadOnly(dbPath)
	if err != nil {
		// A live hub holds the database lock. Fall back to the hub's HTTP
		// status API for what it can verify (token via /v1/wake/status);
		// the rest is skipped, never failed.
		checks = append(checks, doctorHTTPTokenChecks(*peer, base, tokenFile, timeout, err)...)
	} else {
		var found bool
		info, found, err = s.PeerInfo(*peer)
		_ = s.Close()
		switch {
		case err != nil:
			checks = append(checks, doctorCheck{name: "token", detail: err.Error()})
		case !found:
			checks = append(checks, doctorCheck{name: "token", detail: "no such peer; run connect (local database)"})
		case !info.Enabled:
			checks = append(checks, doctorCheck{name: "token", detail: "peer token is revoked (local database)"})
		default:
			checks = append(checks, doctorCheck{ok: true, name: "token", detail: "peer exists and is enabled (local database)"})
		}
		if found {
			checks = append(checks, doctorACLCheck(info, *allow))
		}
	}
	checks = append(checks, doctorAdapterCheck(*peer, *wakePath, *adapterTimeout))
	checks = append(checks, doctorWakeCheck(base, tokenFile, timeout))
	failures := 0
	for _, c := range checks {
		label := "FAIL"
		switch {
		case c.ok:
			label = "OK"
		case c.skip:
			label = "SKIP"
		}
		if !c.ok && !c.skip {
			failures++
		}
		if _, err := fmt.Fprintf(out, "%s %s: %s\n", label, c.name, c.detail); err != nil {
			return err
		}
	}
	if failures > 0 {
		return fmt.Errorf("doctor: %d check(s) failed", failures)
	}
	return nil
}

// doctorACLCheck verifies the peer's send permissions: every edge named by
// --allow (or, without it, at least one edge) must exist.
func doctorACLCheck(info store.PeerInfo, allow string) doctorCheck {
	c := doctorCheck{name: "acl"}
	missing := []string{}
	if allow != "" {
		for _, want := range strings.Split(allow, ",") {
			edge := false
			for _, have := range info.Allowed {
				if have == want || have == "*" {
					edge = true
					break
				}
			}
			if !edge {
				missing = append(missing, want)
			}
		}
	} else if len(info.Allowed) == 0 {
		missing = append(missing, "(peer has no ACL edges and cannot send)")
	}
	if len(missing) > 0 {
		c.detail = "missing edge(s): " + strings.Join(missing, ", ")
	} else {
		c.ok, c.detail = true, "allowed: "+strings.Join(info.Allowed, ", ")+" (local database)"
	}
	return c
}

// doctorHTTPTokenChecks is the locked-database fallback: with --token-file it
// asks the live hub's /v1/wake/status who the token belongs to (source: hub
// API). ACL edges are not exposed by the API, so that check skips.
func doctorHTTPTokenChecks(peer, base, tokenFile string, timeout time.Duration, dbErr error) []doctorCheck {
	note := "database unavailable (hub running?): " + dbErr.Error()
	skip := func(name, detail string) doctorCheck { return doctorCheck{skip: true, name: name, detail: detail} }
	acl := skip("acl", "ACL edges are not exposed by the hub API; "+note)
	if tokenFile == "" {
		return []doctorCheck{skip("token", note+"; no --token-file for the hub API fallback"), acl}
	}
	token, err := readToken(tokenFile)
	if err != nil {
		return []doctorCheck{skip("token", note+"; token file: "+err.Error()), acl}
	}
	cl, err := client.New(client.Config{BaseURL: base, Token: token, Timeout: timeout})
	if err != nil {
		return []doctorCheck{skip("token", note+"; "+err.Error()), acl}
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var st wake.Status
	err = cl.Do(ctx, http.MethodGet, "/v1/wake/status", nil, &st)
	switch {
	case err == nil && st.Peer == peer:
		return []doctorCheck{{ok: true, name: "token", detail: "peer exists and is enabled (hub API; database locked)"}, acl}
	case err == nil:
		return []doctorCheck{{name: "token", detail: fmt.Sprintf("token authenticates as peer %q, not %q (hub API)", st.Peer, peer)}, acl}
	}
	var he *client.HTTPError
	if errors.As(err, &he) && (he.Status == http.StatusUnauthorized || he.Status == http.StatusForbidden) {
		return []doctorCheck{{name: "token", detail: "hub rejected the token (hub API): " + he.Error()}, acl}
	}
	return []doctorCheck{skip("token", note+"; hub API fallback unavailable: "+err.Error()), acl}
}

// doctorAdapterCheck verifies the peer's wake config entry and that the
// configured adapter is reachable: a webhook HEAD/POST dry-run, an exec path
// existence check, or a config-only note for mcp-event and none adapters.
func doctorAdapterCheck(peer, wakePath string, timeout time.Duration) doctorCheck {
	c := doctorCheck{name: "adapter"}
	cfg, err := loadWakeConfigForEdit(wakePath)
	if err != nil {
		c.detail = err.Error()
		return c
	}
	p, ok := cfg.Peers[peer]
	if !ok {
		c.detail = "no wake config entry for this peer; run connect"
		return c
	}
	switch p.Adapter {
	case "webhook":
		if err := webhookDryRun(p.WebhookURL, timeout); err != nil {
			c.detail = err.Error()
		} else {
			c.ok, c.detail = true, "webhook reachable: "+p.WebhookURL
		}
	case "exec":
		if err := execPathExists(p.ExecArgv); err != nil {
			c.detail = err.Error()
		} else {
			c.ok, c.detail = true, "exec command exists: "+strings.Join(p.ExecArgv, " ")
		}
	case "mcp-event":
		c.ok, c.detail = true, "mcp-event configured; requires serve --mcp --oauth-issuer"
	case "poll":
		c.ok, c.detail = true, "adapter poll: long-poll only (enqueue otherwise); requires serve --longpoll"
	default:
		c.ok, c.detail = true, "enqueue only (adapter none); poll peers also need serve --longpoll"
	}
	return c
}

// webhookDryRun probes a wake webhook: a HEAD, falling back to a POST with a
// dry-run body when the endpoint answers 405. Any 2xx/3xx is reachable.
func webhookDryRun(rawURL string, timeout time.Duration) error {
	hc := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, rawURL, nil)
	if err != nil {
		return fmt.Errorf("webhook %s: %w", rawURL, err)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("webhook %s unreachable: %s", rawURL, err)
	}
	status := resp.StatusCode
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()
	if status == http.StatusMethodNotAllowed {
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, rawURL, strings.NewReader(`{"dry_run":true}`))
		if err != nil {
			return fmt.Errorf("webhook %s: %w", rawURL, err)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err = hc.Do(req)
		if err != nil {
			return fmt.Errorf("webhook %s unreachable: %s", rawURL, err)
		}
		status = resp.StatusCode
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
	}
	if status >= 400 {
		return fmt.Errorf("webhook %s answered status %d", rawURL, status)
	}
	return nil
}

func execPathExists(argv []string) error {
	if len(argv) == 0 || argv[0] == "" {
		return errors.New("exec adapter has an empty command")
	}
	if strings.ContainsRune(argv[0], os.PathSeparator) {
		info, err := os.Stat(argv[0])
		if err != nil {
			return fmt.Errorf("exec command %s: %w", argv[0], err)
		}
		if info.IsDir() {
			return fmt.Errorf("exec command %s is a directory", argv[0])
		}
		return nil
	}
	if _, err := exec.LookPath(argv[0]); err != nil {
		return fmt.Errorf("exec command %s not found in PATH", argv[0])
	}
	return nil
}

// doctorWakeCheck reports the peer's last recorded wake decision from a live
// hub. It is never a failure: without a reachable hub or a token file there
// is simply nothing to report.
func doctorWakeCheck(base, tokenFile string, timeout time.Duration) doctorCheck {
	c := doctorCheck{skip: true, name: "wake", detail: "no --token-file; live wake status not queried"}
	if tokenFile == "" {
		return c
	}
	token, err := readToken(tokenFile)
	if err != nil {
		c.detail = "token file: " + err.Error()
		return c
	}
	cl, err := client.New(client.Config{BaseURL: base, Token: token, Timeout: timeout})
	if err != nil {
		c.detail = err.Error()
		return c
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var st wake.Status
	if err := cl.Do(ctx, http.MethodGet, "/v1/wake/status", nil, &st); err != nil {
		c.detail = "live wake status unavailable (" + err.Error() + ")"
		return c
	}
	c.ok, c.skip = true, false
	if st.Last == nil {
		c.detail = fmt.Sprintf("adapter %s, breaker %s; no wake decision recorded yet (hub API)", st.Adapter, st.Breaker)
		return c
	}
	outcome := st.Last.Outcome
	if outcome == "" {
		outcome = "suppressed"
	}
	c.detail = fmt.Sprintf("adapter %s, breaker %s; last wake: effective=%v reason=%s outcome=%s attempts=%d (hub API)",
		st.Adapter, st.Breaker, st.Last.Effective, st.Last.Reason, outcome, st.Last.Attempts)
	return c
}
