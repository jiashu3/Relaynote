// Relaynote / 捎信: durable addressed messages, without remote execution.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"relaynote/internal/api"
	"relaynote/internal/client"
	"relaynote/internal/outbox"
	"relaynote/internal/store"
	"runtime"
	"strings"
	"syscall"
	"time"
)

const version = "0.3.0-preview"

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func emit(w io.Writer, v any) error { return json.NewEncoder(w).Encode(v) }
func flags(name string) *flag.FlagSet {
	f := flag.NewFlagSet(name, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	return f
}
func run(args []string, out io.Writer) error {
	global := flags("relaynote")
	db := global.String("db", "state/relaynote.db", "local hub database")
	base := global.String("url", "http://127.0.0.1:8787", "hub URL; remote URLs require HTTPS")
	tokenFile := global.String("token-file", "", "private node token file")
	ca := global.String("ca-file", "", "additional trusted CA PEM file")
	proxy := global.String("proxy", "", "explicit HTTP(S) proxy URL")
	envProxy := global.Bool("env-proxy", false, "opt in to environment proxy variables")
	outboxPath := global.String("outbox", "state/outbox.db", "durable pending submissions database")
	timeout := global.Duration("timeout", 15*time.Second, "request timeout")
	if err := global.Parse(args); err != nil {
		return err
	}
	if global.NArg() == 0 {
		return errors.New("usage: relaynote [global flags] provision|manage|serve|send|reply|claim|ack|get|flush|version; see README.md")
	}
	command, rest := global.Arg(0), global.Args()[1:]
	if command == "version" {
		return emit(out, map[string]string{"version": version, "protocol": "tailmsg-v1", "os": runtime.GOOS, "arch": runtime.GOARCH, "developer": "涟漪工场有限公司（Ripplelab Limited）", "website": "https://www.ripplelab.hk/"})
	}
	switch command {
	case "provision", "manage":
		return admin(command, rest, *db, out)
	case "serve":
		return serve(rest, *db, out)
	}
	token, err := readToken(*tokenFile)
	if err != nil {
		return err
	}
	c, err := client.New(client.Config{BaseURL: *base, Token: token, CAFile: *ca, ProxyURL: *proxy, UseEnvProxy: *envProxy, Timeout: *timeout})
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var route string
	var body any
	method := http.MethodPost
	f := flags(command)
	switch command {
	case "send", "reply":
		to := f.String("to", "", "recipient for send")
		parent := f.String("parent", "", "parent ID for reply")
		text := f.String("body", "", "message body")
		key := f.String("client-id", "", "stable idempotency key; reuse on retries")
		ttl := f.Int("ttl", 604800, "delivery TTL seconds")
		if err = f.Parse(rest); err != nil {
			return err
		}
		if f.NArg() != 0 {
			return errors.New("unexpected arguments")
		}
		if *key == "" {
			return errors.New("--client-id required")
		}
		payload := map[string]any{"body": *text, "client_id": *key, "ttl": *ttl}
		route = "/v1/messages"
		if command == "send" {
			payload["to"] = *to
		} else {
			route += "/" + *parent + "/reply"
		}
		validate := store.SendRequest{Body: *text, ClientID: *key, TTL: *ttl}
		parentID := ""
		if command == "send" {
			validate.To = *to
		} else {
			parentID = *parent
			if !regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`).MatchString(parentID) {
				return errors.New("--parent must be a message UUID")
			}
		}
		if e := store.ValidateSend(validate, parentID); e != nil {
			return e
		}
		box, e := outbox.New(*outboxPath)
		if e != nil {
			return e
		}
		defer box.Close()
		entry, e := box.Enqueue(*base, token, route, *key, payload)
		if e != nil {
			return e
		}
		var result any
		if e = c.Do(ctx, http.MethodPost, entry.Route, entry.Body, &result); e != nil {
			return fmt.Errorf("submission remains in outbox; retry same request or flush: %w", e)
		}
		if e = box.Complete(entry.Key); e != nil {
			return fmt.Errorf("accepted but outbox cleanup failed; retry safely: %w", e)
		}
		return emit(out, result)
	case "outbox-list", "outbox-drop":
		key := f.String("key", "", "pending entry key to explicitly discard")
		if err = f.Parse(rest); err != nil {
			return err
		}
		if f.NArg() != 0 {
			return errors.New("unexpected arguments")
		}
		box, e := outbox.New(*outboxPath)
		if e != nil {
			return e
		}
		defer box.Close()
		entries, e := box.Pending(*base, token)
		if e != nil {
			return e
		}
		if command == "outbox-list" {
			for _, entry := range entries {
				if e = emit(out, map[string]string{"key": entry.Key, "route": entry.Route, "endpoint": entry.Endpoint}); e != nil {
					return e
				}
			}
			return nil
		}
		if *key == "" {
			return errors.New("--key required; outbox-drop permanently discards this pending submission")
		}
		for _, entry := range entries {
			if entry.Key == *key {
				if e = box.Complete(entry.Key); e != nil {
					return e
				}
				return emit(out, map[string]string{"discarded": entry.Key})
			}
		}
		return errors.New("pending entry not found for this endpoint and identity")
	case "flush":
		if len(rest) != 0 {
			return errors.New("flush takes no arguments")
		}
		box, e := outbox.New(*outboxPath)
		if e != nil {
			return e
		}
		defer box.Close()
		entries, e := box.Pending(*base, token)
		if e != nil {
			return e
		}
		failures := 0
		for _, entry := range entries {
			var result any
			if e = c.Do(ctx, http.MethodPost, entry.Route, entry.Body, &result); e != nil {
				failures++
				if emitErr := emit(out, map[string]string{"pending": entry.Key, "error": e.Error()}); emitErr != nil {
					return emitErr
				}
				continue
			}
			if e = box.Complete(entry.Key); e != nil {
				return e
			}
			if e = emit(out, result); e != nil {
				return e
			}
		}
		if failures > 0 {
			return fmt.Errorf("%d pending submissions retained; other entries processed", failures)
		}
		return nil
	case "claim":
		limit := f.Int("limit", 10, "maximum claims")
		lease := f.Int("lease", 300, "lease seconds")
		if err = f.Parse(rest); err != nil {
			return err
		}
		body = map[string]int{"limit": *limit, "lease": *lease}
		route = "/v1/inbox/claim"
	case "ack":
		id := f.String("id", "", "message ID")
		receipt := f.String("receipt", "", "lease receipt (use --receipt=VALUE)")
		if err = f.Parse(rest); err != nil {
			return err
		}
		route = "/v1/messages/" + *id + "/ack"
		body = map[string]string{"receipt": *receipt}
	case "get":
		id := f.String("id", "", "message ID")
		if err = f.Parse(rest); err != nil {
			return err
		}
		route = "/v1/messages/" + *id
		method = http.MethodGet
	default:
		return errors.New("unknown command")
	}
	if f.NArg() != 0 {
		return errors.New("unexpected arguments")
	}
	var result any
	if err = c.Do(ctx, method, route, body, &result); err != nil {
		return err
	}
	return emit(out, result)
}

func readToken(path string) (string, error) {
	if path == "" {
		return "", errors.New("--token-file required")
	}
	info, e := os.Lstat(path)
	if e != nil {
		return "", e
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("token file must be a regular file, not symlink")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return "", errors.New("token file must be mode 0600")
	}
	if info.Size() > 1024 {
		return "", errors.New("token file too large")
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		return "", e
	}
	return strings.TrimSpace(string(raw)), nil
}

func admin(command string, args []string, path string, out io.Writer) error {
	f := flags(command)
	peer := f.String("peer", "", "node name")
	allowed := f.String("allow", "", "comma-separated destinations; empty denies sends")
	action := f.String("action", "", "revoke, rotate, permissions")
	tokenPath := f.String("out", "", "new exclusive private token file")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return errors.New("unexpected arguments")
	}
	acl := []string{}
	if *allowed != "" {
		acl = strings.Split(*allowed, ",")
	}
	needsToken := command == "provision" || *action == "rotate"
	var token string
	if needsToken {
		if *tokenPath == "" {
			return errors.New("--out is required")
		}
		var err error
		token, err = store.NewToken()
		if err != nil {
			return err
		}
		if err = os.MkdirAll(filepath.Dir(*tokenPath), 0700); err != nil {
			return err
		}
		file, err := os.OpenFile(*tokenPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		if _, err = file.WriteString(token + "\n"); err == nil {
			err = file.Sync()
		}
		closeErr := file.Close()
		if err == nil {
			err = closeErr
		}
		if err != nil {
			_ = os.Remove(*tokenPath)
			return err
		}
	}
	committed := false
	defer func() {
		if needsToken && !committed {
			_ = os.Remove(*tokenPath)
		}
	}()
	s, err := store.New(path)
	if err != nil {
		return fmt.Errorf("open hub database (stop hub before local administration): %w", err)
	}
	defer s.Close()
	if command == "provision" {
		err = s.Provision(*peer, acl, token)
	} else {
		err = s.Manage(*peer, *action, acl, token)
	}
	if err != nil {
		return err
	}
	committed = true
	return emit(out, map[string]any{"peer": *peer, "operation": command, "ok": true})
}

func serve(args []string, path string, out io.Writer) error {
	f := flags("serve")
	listen := f.String("listen", "127.0.0.1:8787", "listen address")
	cert := f.String("tls-cert", "", "TLS certificate PEM file")
	key := f.String("tls-key", "", "TLS private key PEM file")
	remote := f.Bool("allow-remote", false, "explicitly allow non-loopback TLS listener")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return errors.New("unexpected arguments")
	}
	host, _, err := net.SplitHostPort(*listen)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	loopback := ip != nil && ip.IsLoopback()
	if !loopback && (!*remote || *cert == "" || *key == "") {
		return errors.New("non-loopback listener requires --allow-remote and TLS certificate/key")
	}
	if (*cert == "") != (*key == "") {
		return errors.New("provide both TLS certificate and key")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if *cert != "" {
		pair, e := tls.LoadX509KeyPair(*cert, *key)
		if e != nil {
			return errors.New("could not load TLS certificate/key")
		}
		tlsConfig.Certificates = []tls.Certificate{pair}
	}
	s, err := store.New(path)
	if err != nil {
		return err
	}
	defer s.Close()
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	defer listener.Close()
	server := &http.Server{Handler: api.New(s), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192, TLSConfig: tlsConfig}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	scheme := "http"
	if *cert != "" {
		scheme = "https"
	}
	if err = emit(out, map[string]string{"listening": scheme + "://" + listener.Addr().String(), "version": version}); err != nil {
		return err
	}
	if *cert != "" {
		err = server.ServeTLS(listener, "", "")
	} else {
		err = server.Serve(listener)
	}
	if errors.Is(err, http.ErrServerClosed) {
		<-shutdownDone
		return nil
	}
	return err
}
