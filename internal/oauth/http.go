// HTTP front for the OAuth server: well-known metadata, register, token and
// the login form. Mirrors dot-bridge's server.py routes, statuses and error
// bodies. Mounted by serve only when --oauth-issuer is set.
package oauth

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// MaxBody caps OAuth request bodies, as in server.py.
const MaxBody = 256 * 1024

// Limiter is a per-key sliding-window rate limiter (one-minute window), used
// for the OAuth and MCP endpoints. It prunes idle entries instead of
// resetting everybody.
type Limiter struct {
	mu   sync.Mutex
	hits map[string][]float64
	now  func() float64
}

// NewLimiter returns a Limiter on the server's clock.
func (s *Server) NewLimiter() *Limiter {
	return &Limiter{hits: map[string][]float64{}, now: s.now}
}

// Limited records a hit for key and reports whether the key exceeds perMin
// hits in the last minute.
func (l *Limiter) Limited(key string, perMin int) bool {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	hits := []float64{}
	for _, t := range l.hits[key] {
		if t > now-60 {
			hits = append(hits, t)
		}
	}
	hits = append(hits, now)
	l.hits[key] = hits
	if len(l.hits) > 5000 {
		for k, v := range l.hits {
			if len(v) == 0 || v[len(v)-1] < now-60 {
				delete(l.hits, k)
			}
		}
	}
	return len(hits) > perMin
}

// ClientIP is the real client IP. X-Forwarded-For is honoured only when the
// TCP peer is a trusted proxy; its last entry is the one the proxy itself
// wrote, anything before it is client-supplied.
func ClientIP(r *http.Request, trustedProxies []string) string {
	peer, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		peer = r.RemoteAddr
	}
	trusted := false
	for _, p := range trustedProxies {
		if peer == p {
			trusted = true
			break
		}
	}
	if !trusted {
		return truncate64(peer)
	}
	xff := r.Header.Values("X-Forwarded-For")
	last := ""
	if len(xff) > 0 {
		parts := strings.Split(strings.Join(xff, ","), ",")
		last = strings.TrimSpace(parts[len(parts)-1])
	}
	if last == "" {
		return truncate64(peer)
	}
	if a := net.ParseIP(last); a != nil {
		return a.String()
	}
	return "invalid"
}

func truncate64(s string) string {
	if len(s) > 64 {
		return s[:64]
	}
	return s
}

// Handler serves the OAuth routes: /.well-known/*, /oauth/*.
type Handler struct {
	Server  *Server
	Limiter *Limiter
}

var scopeZh = map[string]string{
	"messages:read":    "读取发给本节点的 Relaynote 消息",
	"messages:send":    "以本节点身份发送消息",
	"events:subscribe": "订阅新消息提醒（message.created）",
}

func write(w http.ResponseWriter, status int, body []byte, ctype string, extra map[string]string) {
	h := w.Header()
	h.Set("Content-Type", ctype+"; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	if strings.HasPrefix(ctype, "text/html") {
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; "+
			"form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
	}
	for k, v := range extra {
		h.Set(k, v)
	}
	w.WriteHeader(status)
	if len(body) > 0 {
		_, _ = w.Write(body)
	}
}

func writeJSON(w http.ResponseWriter, status int, obj any, extra map[string]string) {
	body, err := json.Marshal(obj)
	if err != nil {
		write(w, 500, nil, "text/plain", nil)
		return
	}
	write(w, status, body, "application/json", extra)
}

func messagePage(title, message string) []byte {
	return []byte(fmt.Sprintf(`<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><title>%s</title></head>`+
		`<body style="font-family:system-ui;max-width:420px;margin:40px auto"><h2>%s</h2>`+
		`<p>%s</p></body></html>`, html.EscapeString(title), html.EscapeString(title), html.EscapeString(message)))
}

func (s *Server) loginPage(rid string, params *authRequest, message string) []byte {
	items := ""
	for _, sc := range strings.Fields(params.Scope) {
		label := sc
		if zh, ok := scopeZh[sc]; ok {
			label = zh
		}
		items += "<li>" + html.EscapeString(label) + "</li>"
	}
	msg := ""
	if message != "" {
		msg = `<p class="err">` + html.EscapeString(message) + "</p>"
	}
	return []byte(`<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>relaynote 登录</title>
<style>body{font-family:system-ui,sans-serif;max-width:420px;margin:40px auto;padding:0 16px}
input{width:100%;padding:10px;margin:6px 0 14px;font-size:16px;box-sizing:border-box}
button{padding:10px 18px;font-size:16px;margin-right:8px}.err{color:#b00}small{color:#666}</style></head>
<body><h2>relaynote 授权</h2><p>客户端请求以下权限：</p><ul>` + items + `</ul>` + msg + `
<form method="post" action="/oauth/authorize" autocomplete="off">
<input type="hidden" name="rid" value="` + html.EscapeString(rid) + `">
<label>口令<input type="password" name="password" autocomplete="current-password" required></label>
<label>验证器 App 里的 6 位数字<input name="totp" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" required></label>
<button type="submit" name="action" value="approve">授权</button>
<button type="submit" name="action" value="deny" formnovalidate>拒绝</button></form>
<p><small>只有枢纽管理员本人可以授权。连续 5 次失败会锁定 15 分钟。</small></p></body></html>`)
}

func readBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	if r.ContentLength < 0 {
		writeJSON(w, 411, map[string]string{"error": "length_required"}, nil)
		return nil, false
	}
	if r.ContentLength > MaxBody {
		writeJSON(w, 413, map[string]string{"error": "too_large"}, nil)
		return nil, false
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, MaxBody+1))
	if err != nil || len(raw) > MaxBody {
		writeJSON(w, 413, map[string]string{"error": "too_large"}, nil)
		return nil, false
	}
	return raw, true
}

func formValues(raw []byte) map[string]string {
	vals, _ := url.ParseQuery(string(raw))
	out := map[string]string{}
	for k, v := range vals {
		if len(v) > 0 {
			out[k] = v[0]
		}
	}
	return out
}

func queryValues(r *http.Request) map[string]string {
	out := map[string]string{}
	for k, v := range r.URL.Query() {
		if len(v) > 0 {
			out[k] = v[0]
		}
	}
	return out
}

func deviceCookie(r *http.Request) string {
	c, err := r.Cookie(DeviceCookie)
	if err != nil {
		return ""
	}
	return c.Value
}

// ServeHTTP routes the OAuth endpoints; any other path gets 404 not_found.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s := h.Server
	ip := ClientIP(r, s.cfg.TrustedProxies)
	switch r.URL.Path {
	case "/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp":
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeJSON(w, 405, map[string]string{"error": "method_not_allowed"}, nil)
			return
		}
		writeJSON(w, 200, s.ProtectedResourceMetadata(), nil)
	case "/.well-known/oauth-authorization-server", "/.well-known/oauth-authorization-server/mcp":
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeJSON(w, 405, map[string]string{"error": "method_not_allowed"}, nil)
			return
		}
		writeJSON(w, 200, s.ASMetadata(), nil)
	case "/oauth/register":
		if r.Method != http.MethodPost {
			writeJSON(w, 404, map[string]string{"error": "not_found"}, nil)
			return
		}
		h.postRegister(w, r, ip)
	case "/oauth/token":
		if r.Method != http.MethodPost {
			writeJSON(w, 404, map[string]string{"error": "not_found"}, nil)
			return
		}
		h.postToken(w, r, ip)
	case "/oauth/authorize":
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			h.getAuthorize(w, r, ip)
			return
		}
		if r.Method == http.MethodPost {
			h.postAuthorize(w, r, ip)
			return
		}
		writeJSON(w, 404, map[string]string{"error": "not_found"}, nil)
	default:
		writeJSON(w, 404, map[string]string{"error": "not_found"}, nil)
	}
}

func (h *Handler) getAuthorize(w http.ResponseWriter, r *http.Request, ip string) {
	s := h.Server
	if h.Limiter.Limited(ip, 30) {
		write(w, 429, messagePage("请求过多", "请稍后再试。"), "text/html", nil)
		return
	}
	kind, val, err := s.StartAuthorize(queryValues(r))
	if err != nil {
		if oe, ok := err.(*Error); ok {
			write(w, oe.Status, messagePage("无法授权", oe.Desc), "text/html", nil)
			return
		}
		write(w, 500, messagePage("错误", "内部错误。"), "text/html", nil)
		return
	}
	if kind == "redirect" {
		write(w, 302, nil, "text/plain", map[string]string{"Location": val})
		return
	}
	params := s.RequestParams(val)
	if params == nil {
		write(w, 400, messagePage("请求已过期", "请重新连接。"), "text/html", nil)
		return
	}
	write(w, 200, s.loginPage(val, params, ""), "text/html", nil)
}

func (h *Handler) postAuthorize(w http.ResponseWriter, r *http.Request, ip string) {
	s := h.Server
	if origin := r.Header.Get("Origin"); origin != "" && origin != s.cfg.Issuer && origin != "null" {
		write(w, 403, messagePage("拒绝", "来源不对。"), "text/html", nil)
		return
	}
	if h.Limiter.Limited(ip, 20) {
		write(w, 429, messagePage("请求过多", "请稍后再试。"), "text/html", nil)
		return
	}
	raw, ok := readBody(w, r)
	if !ok {
		return
	}
	form := formValues(raw)
	kind, val, extra, err := s.FinishAuthorize(form, ip, deviceCookie(r))
	if err != nil {
		write(w, 500, messagePage("错误", "内部错误。"), "text/html", nil)
		return
	}
	switch kind {
	case "redirect":
		write(w, 302, nil, "text/plain", extraWith(extra, "Location", val))
	case "expired":
		write(w, 400, messagePage("请求已过期", val), "text/html", nil)
	default: // retry
		params := s.RequestParams(form["rid"])
		if params == nil {
			write(w, 400, messagePage("请求已过期", "请重新连接。"), "text/html", nil)
			return
		}
		write(w, 200, s.loginPage(form["rid"], params, val), "text/html", nil)
	}
}

func extraWith(extra map[string]string, k, v string) map[string]string {
	out := map[string]string{k: v}
	for key, val := range extra {
		out[key] = val
	}
	return out
}

func (h *Handler) postRegister(w http.ResponseWriter, r *http.Request, ip string) {
	if h.Limiter.Limited(ip, 10) {
		writeJSON(w, 429, map[string]string{"error": "slow_down"}, nil)
		return
	}
	raw, ok := readBody(w, r)
	if !ok {
		return
	}
	var body map[string]any
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &body); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid_client_metadata"}, nil)
			return
		}
	}
	if body == nil {
		body = map[string]any{}
	}
	res, err := h.Server.Register(body)
	if err != nil {
		writeOAuthError(w, err)
		return
	}
	writeJSON(w, 201, res, nil)
}

func (h *Handler) postToken(w http.ResponseWriter, r *http.Request, ip string) {
	if h.Limiter.Limited(ip, 30) {
		writeJSON(w, 429, map[string]string{"error": "slow_down"}, nil)
		return
	}
	raw, ok := readBody(w, r)
	if !ok {
		return
	}
	res, err := h.Server.Token(formValues(raw))
	if err != nil {
		writeOAuthError(w, err)
		return
	}
	writeJSON(w, 200, res, map[string]string{"Pragma": "no-cache"})
}

func writeOAuthError(w http.ResponseWriter, err error) {
	if oe, ok := err.(*Error); ok {
		writeJSON(w, oe.Status, map[string]string{"error": oe.Err, "error_description": oe.Desc}, nil)
		return
	}
	writeJSON(w, 500, map[string]string{"error": "server_error"}, nil)
}
