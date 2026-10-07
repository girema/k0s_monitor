package web

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/version"
	"k8s.io/client-go/kubernetes/fake"

	"k0s_monitor/internal/auth"
	"k0s_monitor/internal/cluster"
	"k0s_monitor/internal/config"
	"k0s_monitor/internal/engine"
	"k0s_monitor/internal/findings"
	"k0s_monitor/internal/store"
	"k0s_monitor/internal/testutil"
	"k0s_monitor/internal/vault"
)

const testPassword = "correct horse battery"

var fixedNow = time.Date(2026, 9, 27, 14, 0, 0, 0, time.UTC)

type testEnv struct {
	t      *testing.T
	srv    *Server
	ts     *httptest.Server
	st     *store.Store
	fleet  *engine.Fleet
	cookie *http.Cookie
	csrf   string
}

func newEnv(t *testing.T, mutate func(*Options)) *testEnv {
	t.Helper()
	return newEnvFor(t, fake.NewClientset(testutil.Objects(t, "../rules/testdata/crashloop.yaml")...), mutate)
}

// newEnvFor is newEnv with the cluster that client serves.
func newEnvFor(t *testing.T, client *fake.Clientset, mutate func(*Options)) *testEnv {
	t.Helper()
	dir := t.TempDir()
	v, _ := vault.New(bytes.Repeat([]byte{1}, vault.KeySize))
	st, err := store.Open(filepath.Join(dir, "db"), v)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	hash, _ := auth.HashPassword(testPassword)
	if err := st.AddUser(auth.User, hash, ""); err != nil {
		t.Fatal(err)
	}

	cfg := config.Default()
	cfg.UI.DefaultMode = "basic"
	cfg.UI.Notify = []string{"fix-now", "fix-today"}
	cfg.Auth.SessionIdle = config.Duration(time.Hour)

	env := &testEnv{t: t, st: st}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	opts := Options{Config: cfg, Store: st, CanStoreClusters: true, Host: "jump-01", URL: "https://jump-01:8443",
		Now: func() time.Time { return fixedNow }}
	if mutate != nil {
		mutate(&opts)
	}
	env.fleet = engine.NewFleet(ctx, engine.Options{
		Store: st, Now: func() time.Time { return fixedNow }, Packs: opts.Packs,
		MinInterval: 20 * time.Millisecond, MaxInterval: 200 * time.Millisecond, PingInterval: 50 * time.Millisecond,
		Connect: func(c config.Cluster, _ time.Duration) (*cluster.Conn, error) {
			return cluster.NewForClient(c.Name, "https://10.0.10.5:6443", client, &version.Info{GitVersion: "v1.36.4+k0s"}), nil
		},
		OnEvent: func(ev engine.Event) {
			if env.srv != nil {
				env.srv.OnEvent(ev)
			}
		},
	})
	t.Cleanup(env.fleet.Stop)
	opts.Fleet = env.fleet
	srv, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	env.srv = srv
	env.ts = httptest.NewTLSServer(srv.Handler())
	t.Cleanup(env.ts.Close)
	if _, err := env.fleet.Add(config.Cluster{Name: "edge-prod", Kubeconfig: "unused"}); err != nil {
		t.Fatal(err)
	}
	env.waitFor(func(e *engine.Engine) bool { return e.State().Evals > 0 })
	return env
}

func (env *testEnv) waitFor(cond func(*engine.Engine) bool) {
	env.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if e := env.fleet.Get("edge-prod"); e != nil && cond(e) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	env.t.Fatal("timed out waiting for the engine")
}

func (env *testEnv) client() *http.Client {
	c := env.ts.Client()
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return c
}

func (env *testEnv) do(method, path string, body io.Reader, hdr map[string]string) *http.Response {
	env.t.Helper()
	req, _ := http.NewRequest(method, env.ts.URL+path, body)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	if env.cookie != nil {
		req.AddCookie(env.cookie)
	}
	resp, err := env.client().Do(req)
	if err != nil {
		env.t.Fatal(err)
	}
	return resp
}

func readBody(t *testing.T, r *http.Response) string {
	t.Helper()
	b, _ := io.ReadAll(r.Body)
	r.Body.Close()
	return string(b)
}

// login signs in through the JSON API and keeps the cookie and CSRF token.
func (env *testEnv) login() {
	env.t.Helper()
	resp := env.do("POST", "/api/v1/session", strings.NewReader(`{"password":"`+testPassword+`"}`), map[string]string{"Content-Type": "application/json"})
	if resp.StatusCode != 200 {
		env.t.Fatalf("login: %d %s", resp.StatusCode, readBody(env.t, resp))
	}
	var lr loginResponse
	json.NewDecoder(resp.Body).Decode(&lr)
	resp.Body.Close()
	for _, c := range resp.Cookies() {
		if c.Name == sessionCookie {
			env.cookie = c
		}
	}
	if env.cookie == nil || lr.CSRF == "" {
		env.t.Fatal("no session cookie or CSRF token")
	}
	if !env.cookie.HttpOnly || !env.cookie.Secure || env.cookie.SameSite != http.SameSiteStrictMode {
		env.t.Errorf("cookie flags: %+v", env.cookie)
	}
	env.csrf = lr.CSRF
}

func mustContain(t *testing.T, body string, parts ...string) {
	t.Helper()
	for _, p := range parts {
		if !strings.Contains(body, p) {
			t.Errorf("page lacks %q", p)
		}
	}
}

func TestSignInRequired(t *testing.T) {
	env := newEnv(t, nil)
	resp := env.do("GET", "/", nil, nil)
	if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(resp.Header.Get("Location"), "/login") {
		t.Errorf("pages redirect to sign-in: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp = env.do("GET", "/api/v1/clusters", nil, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("the API answers 401: %d", resp.StatusCode)
	}
	resp = env.do("GET", "/login", nil, nil)
	body := readBody(t, resp)
	mustContain(t, body, "Sign in", `name="password"`)
	if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "script-src 'self'") || strings.Contains(csp, "unsafe") {
		t.Errorf("CSP = %q", csp)
	}
	if resp.Header.Get("X-Frame-Options") != "DENY" {
		t.Error("frames must be denied")
	}
}

func TestLoginForm(t *testing.T) {
	env := newEnv(t, nil)
	form := url.Values{"password": {"wrong password"}, "next": {"/c/edge-prod"}}
	resp := env.do("POST", "/login", strings.NewReader(form.Encode()), map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(readBody(t, resp), "Wrong user name or password") {
		t.Errorf("wrong password: %d", resp.StatusCode)
	}
	form.Set("password", testPassword)
	form.Set("next", "//evil.example/steal")
	resp = env.do("POST", "/login", strings.NewReader(form.Encode()), map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/" {
		t.Errorf("sign-in redirects only to local pages: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	// A cross-site sign-in form is refused.
	resp = env.do("POST", "/login", strings.NewReader(form.Encode()), map[string]string{
		"Content-Type": "application/x-www-form-urlencoded", "Origin": "https://evil.example"})
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("cross-site sign-in: %d", resp.StatusCode)
	}
	log, _ := env.st.AuditLog(10)
	if len(log) < 2 || log[0].Action != "sign-in" || log[1].Action != "sign-in.failed" {
		t.Errorf("audit = %+v", log)
	}
	for _, c := range []struct {
		hdr  map[string]string
		want int
	}{
		// What Edge and Chrome send for the page's own form.
		{map[string]string{"Origin": "null", "Sec-Fetch-Site": "same-origin"}, http.StatusSeeOther},
		{map[string]string{"Origin": env.ts.URL, "Sec-Fetch-Site": "same-origin"}, http.StatusSeeOther},
		// Behind a proxy that rewrites the host, the browser still knows.
		{map[string]string{"Origin": "https://jump-01.lan:8443", "Sec-Fetch-Site": "same-origin"}, http.StatusSeeOther},
		{map[string]string{"Origin": env.ts.URL, "Sec-Fetch-Site": "cross-site"}, http.StatusForbidden},
		{map[string]string{"Origin": "https://other.lan", "Sec-Fetch-Site": "same-site"}, http.StatusForbidden},
		// Without Sec-Fetch-Site, Origin decides, and null is refused.
		{map[string]string{"Origin": "null"}, http.StatusForbidden},
		{map[string]string{"Origin": env.ts.URL}, http.StatusSeeOther},
	} {
		c.hdr["Content-Type"] = "application/x-www-form-urlencoded"
		if resp := env.do("POST", "/login", strings.NewReader(form.Encode()), c.hdr); resp.StatusCode != c.want {
			t.Errorf("sign-in with %v: %d, want %d", c.hdr, resp.StatusCode, c.want)
		}
	}
}

func TestLoginRateLimit(t *testing.T) {
	env := newEnv(t, nil)
	var last int
	for i := 0; i < 6; i++ {
		resp := env.do("POST", "/api/v1/session", strings.NewReader(`{"password":"nope nope nope"}`), nil)
		last = resp.StatusCode
		resp.Body.Close()
	}
	if last != http.StatusTooManyRequests {
		t.Errorf("after 5 failures sign-in is refused for a while, got %d", last)
	}
	resp := env.do("POST", "/api/v1/session", strings.NewReader(`{"password":"`+testPassword+`"}`), nil)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("even the right password waits: %d", resp.StatusCode)
	}
}

func TestPagesBasicAndFull(t *testing.T) {
	env := newEnv(t, nil)
	env.login()
	env.waitFor(func(e *engine.Engine) bool { return len(e.State().Findings) > 0 })

	body := readBody(t, env.do("GET", "/", nil, nil))
	mustContain(t, body, "All clusters", "edge-prod", "Needs attention", "Fix first:", "The app payments-api keeps crashing")

	body = readBody(t, env.do("GET", "/c/edge-prod", nil, nil))
	mustContain(t, body, "edge-prod needs your attention", "Fix these first", "What we checked",
		"The app payments-api keeps crashing", "Also affected:", "Show me what to fix")
	if strings.Contains(body, "pod.crashloop") {
		t.Error("Basic mode shows no rule IDs")
	}
	// The sidebar counts what the sentence counts: apps, not pods.
	if m := regexp.MustCompile(`<div class="meta">\d+ servers? · (\d+ apps?)</div>`).FindStringSubmatch(body); m == nil || !strings.Contains(body, " of "+m[1]+" run normally.") {
		t.Errorf("the sidebar says %q", m)
	}

	resp := env.do("GET", "/c/edge-prod?mode=full", nil, nil)
	body = readBody(t, resp)
	mustContain(t, body, "Cluster health", "/ 100", "Fix first", "CrashLoopBackOff", `data-mode="full"`, "Data sources")
	if !regexp.MustCompile(`<div class="meta">[^<]* · \d+ nodes? · \d+ pods?</div>`).MatchString(body) {
		t.Error("Full mode's sidebar counts nodes and pods")
	}
	var modeCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "mode" {
			modeCookie = c
		}
	}
	if modeCookie == nil || modeCookie.Value != "full" {
		t.Fatal("?mode=full is remembered in a cookie")
	}

	body = readBody(t, env.do("GET", "/c/edge-prod/problems", nil, nil))
	mustContain(t, body, "Problems", "Fix now", "How to fix")
	body = readBody(t, env.do("GET", "/c/edge-prod/problems?mode=full&priority=P1", nil, nil))
	mustContain(t, body, "Issues", "pod.crashloop", "symptom", "deploy.unavailable", "Export JSON")

	crash := findingByRule(env, "pod.crashloop")
	body = readBody(t, env.do("GET", "/c/edge-prod/problems/"+crash.ID+"?mode=basic", nil, nil))
	mustContain(t, body, "What happened", "What to do", "kubectl -n shop logs", "on it", "Remind me later", "Show technical details")
	body = readBody(t, env.do("GET", "/c/edge-prod/problems/"+crash.ID+"?mode=full", nil, nil))
	mustContain(t, body, "EVIDENCE", "Exit code", "Likely cause", "Acknowledge", "Snooze", "/c/edge-prod/pods/shop/payments-api-")

	resp = env.do("GET", "/c/nope", nil, nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown cluster: %d", resp.StatusCode)
	}
	body = readBody(t, env.do("GET", "/settings", nil, nil))
	mustContain(t, body, "Change your password", "signed in as admin", `id="users"`, "Audit log", "sign-in")
}

func findingByRule(env *testEnv, rule string) *findings.Finding {
	for _, f := range env.fleet.Get("edge-prod").State().Findings {
		if f.RuleID == rule {
			return f
		}
	}
	env.t.Fatalf("no %s finding", rule)
	return nil
}

func TestCSRF(t *testing.T) {
	env := newEnv(t, nil)
	env.login()
	crash := findingByRule(env, "pod.crashloop")
	path := "/api/v1/clusters/edge-prod/findings/" + crash.ID + "/ack"
	resp := env.do("POST", path, nil, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("a POST without the CSRF token is refused: %d", resp.StatusCode)
	}
	resp = env.do("POST", path, nil, map[string]string{"X-CSRF-Token": env.csrf, "Origin": "https://evil.example"})
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("a cross-origin POST is refused even with a token: %d", resp.StatusCode)
	}
	resp = env.do("POST", path, nil, map[string]string{"X-CSRF-Token": env.csrf})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("ack: %d %s", resp.StatusCode, readBody(t, resp))
	}
	resp.Body.Close()
}

func TestAcknowledgeAndSnooze(t *testing.T) {
	env := newEnv(t, nil)
	env.login()
	crash := findingByRule(env, "pod.crashloop")
	hdr := map[string]string{"X-CSRF-Token": env.csrf}
	base := "/api/v1/clusters/edge-prod/findings/" + crash.ID
	badge := regexp.MustCompile(`>Problems<span class="count[^"]*">(\d+)</span>`)
	badgeOf := func(body string) int {
		if m := badge.FindStringSubmatch(body); m != nil {
			return mustAtoi(t, m[1])
		}
		return 0
	}
	before := badgeOf(readBody(t, env.do("GET", "/c/edge-prod/problems", nil, nil)))

	resp := env.do("POST", base+"/ack", nil, hdr)
	var out struct{ Finding *findings.Finding }
	json.NewDecoder(resp.Body).Decode(&out)
	resp.Body.Close()
	if out.Finding == nil || out.Finding.State != findings.StateAcknowledged {
		t.Fatalf("after ack: %+v", out.Finding)
	}
	// Acknowledged problems leave the Basic lists but stay reachable.
	body := readBody(t, env.do("GET", "/c/edge-prod/problems", nil, nil))
	if strings.Contains(body, "The app payments-api keeps crashing") {
		t.Error("an acknowledged problem is hidden from the default list")
	}
	mustContain(t, body, "Show 1 set aside")
	// The menu's badge counts what nobody has taken, as the list does.
	if after := badgeOf(body); before == 0 || after != before-1 {
		t.Errorf("problems badge: before %v, after %v", before, after)
	}

	resp = env.do("POST", base+"/snooze", strings.NewReader(`{"duration":"4h"}`), hdr)
	json.NewDecoder(resp.Body).Decode(&out)
	resp.Body.Close()
	if out.Finding.State != findings.StateSnoozed || out.Finding.SnoozedUntil == nil || !out.Finding.SnoozedUntil.Equal(fixedNow.Add(4*time.Hour)) {
		t.Errorf("after snooze: %+v", out.Finding)
	}
	resp = env.do("POST", base+"/snooze", strings.NewReader(`{"duration":"-1h"}`), hdr)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("a snooze into the past is refused: %d", resp.StatusCode)
	}

	// The HTML form reopens it.
	form := url.Values{"csrf": {env.csrf}, "action": {"reopen"}, "back": {"/c/edge-prod/problems"}}
	resp = env.do("POST", "/c/edge-prod/problems/"+crash.ID+"/state", strings.NewReader(form.Encode()),
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/c/edge-prod/problems" {
		t.Errorf("reopen form: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	if f := env.fleet.Get("edge-prod").State().Finding(crash.ID); f.State != findings.StateOpen {
		t.Errorf("after reopen: %s", f.State)
	}
	log, _ := env.st.AuditLog(10)
	if log[0].Action != "finding.reopen" || log[1].Action != "finding.snooze" || log[2].Action != "finding.ack" {
		t.Errorf("audit = %+v", log[:3])
	}
}

func TestAPI(t *testing.T) {
	env := newEnv(t, nil)
	env.login()
	env.waitFor(func(e *engine.Engine) bool { return e.State().Health != nil })

	var cs []apiCluster
	resp := env.do("GET", "/api/v1/clusters", nil, nil)
	json.NewDecoder(resp.Body).Decode(&cs)
	resp.Body.Close()
	if len(cs) != 1 || cs[0].Name != "edge-prod" || cs[0].Health == nil || cs[0].TopIssue == nil || cs[0].Counts[findings.P1] != 1 || !cs[0].K0s {
		t.Fatalf("clusters = %+v", cs)
	}
	var fs []*findings.Finding
	resp = env.do("GET", "/api/v1/clusters/edge-prod/findings?symptoms=false", nil, nil)
	json.NewDecoder(resp.Body).Decode(&fs)
	resp.Body.Close()
	var problems, suggestions []*findings.Finding
	for _, f := range fs {
		if f.IsHygiene() {
			suggestions = append(suggestions, f)
		} else {
			problems = append(problems, f)
		}
	}
	// The payments-api pods have no limits and no probes: suggestions, not
	// problems.
	if len(problems) != 1 || problems[0].RuleID != "pod.crashloop" || len(suggestions) == 0 {
		t.Errorf("roots only: problems %d, suggestions %d", len(problems), len(suggestions))
	}
	resp = env.do("GET", "/api/v1/clusters/edge-prod/findings?category=network", nil, nil)
	fs = nil
	json.NewDecoder(resp.Body).Decode(&fs)
	resp.Body.Close()
	if len(fs) != 1 || fs[0].RuleID != "svc.no-endpoints" {
		t.Errorf("by category: %+v", fs)
	}
	resp = env.do("GET", "/api/v1/clusters/edge-prod/findings/"+fs[0].ID, nil, nil)
	if resp.StatusCode != 200 {
		t.Errorf("finding detail: %d", resp.StatusCode)
	}
	resp.Body.Close()

	resp = env.do("PATCH", "/api/v1/settings", strings.NewReader(`{"defaultMode":"full"}`), map[string]string{"X-CSRF-Token": env.csrf})
	if resp.StatusCode != 200 {
		t.Errorf("settings: %d %s", resp.StatusCode, readBody(t, resp))
	}
	resp.Body.Close()
	body := readBody(t, env.do("GET", "/c/edge-prod", nil, nil))
	mustContain(t, body, `data-mode="full"`)

	metrics := readBody(t, env.do("GET", "/metrics", nil, nil))
	mustContain(t, metrics, `k0s_monitor_findings{cluster="edge-prod",priority="P1"} 1`, `k0s_monitor_cluster_up{cluster="edge-prod"} 1`)
}

func TestNotificationsAndStream(t *testing.T) {
	env := newEnv(t, func(o *Options) {})
	env.srv.notify.setDelay(10 * time.Millisecond)
	env.login()

	// Follow the stream while a second cluster is added: its first
	// evaluation produces one summary notification.
	req, _ := http.NewRequest("GET", env.ts.URL+"/api/v1/stream", nil)
	req.AddCookie(env.cookie)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := env.client().Do(req.WithContext(ctx))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("content type %q", resp.Header.Get("Content-Type"))
	}
	if _, err := env.fleet.Add(config.Cluster{Name: "retail-eu", Kubeconfig: "unused"}); err != nil {
		t.Fatal(err)
	}
	sc := bufio.NewScanner(resp.Body)
	gotState, gotNote := false, false
	for sc.Scan() && !(gotState && gotNote) {
		line := sc.Text()
		if line == "event: state" {
			gotState = true
		}
		if line == "event: notification" {
			gotNote = true
		}
	}
	if !gotState || !gotNote {
		t.Fatalf("stream: state %v notification %v", gotState, gotNote)
	}

	var out struct {
		Notifications []store.Notification
		Unread        int
	}
	r := env.do("GET", "/api/v1/notifications", nil, nil)
	json.NewDecoder(r.Body).Decode(&out)
	r.Body.Close()
	var summary *store.Notification
	for i, n := range out.Notifications {
		if n.Cluster == "retail-eu" {
			summary = &out.Notifications[i]
		}
	}
	if summary == nil || summary.Kind != "opened" || summary.Priority != findings.P1 || out.Unread == 0 {
		t.Fatalf("notifications = %+v", out)
	}
	if !strings.Contains(summary.PlainTitle, "the app payments-api keeps crashing") {
		t.Errorf("plain title = %q", summary.PlainTitle)
	}
	r = env.do("POST", "/api/v1/notifications/read", strings.NewReader(`{"upTo":0}`), map[string]string{"X-CSRF-Token": env.csrf})
	body := readBody(t, r)
	if !strings.Contains(body, `"unread": 0`) {
		t.Errorf("mark read: %s", body)
	}
}

func TestAllowFrom(t *testing.T) {
	env := newEnv(t, func(o *Options) { o.Config.AllowFrom = []string{"192.168.10.25"} })
	// The test client connects from 127.0.0.1, which is always allowed.
	resp := env.do("GET", "/login", nil, nil)
	if resp.StatusCode != 200 {
		t.Errorf("loopback is always allowed: %d", resp.StatusCode)
	}
	resp.Body.Close()
	h := env.srv.Handler()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/login", nil)
	req.RemoteAddr = "192.168.10.99:51000"
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("other addresses are refused: %d", rec.Code)
	}
	req.RemoteAddr = "192.168.10.25:51000"
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("the allowed address may open the UI: %d", rec.Code)
	}
}

func TestNoAuthOnlyOnLocalhost(t *testing.T) {
	env := newEnv(t, func(o *Options) { o.NoAuth = true })
	body := readBody(t, env.do("GET", "/", nil, nil))
	mustContain(t, body, "All clusters", "Sign-in is off")
	h := env.srv.Handler()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "attacker.example"
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("without sign-in, other host names are refused (DNS rebinding): %d", rec.Code)
	}
}

func TestPasswordChange(t *testing.T) {
	env := newEnv(t, nil)
	env.login()
	hdr := map[string]string{"X-CSRF-Token": env.csrf}
	resp := env.do("POST", "/api/v1/password", strings.NewReader(`{"current":"wrong wrong wrong","new":"another long password"}`), hdr)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("wrong current password: %d", resp.StatusCode)
	}
	resp = env.do("POST", "/api/v1/password", strings.NewReader(`{"current":"`+testPassword+`","new":"short"}`), hdr)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("short new password: %d", resp.StatusCode)
	}
	resp = env.do("POST", "/api/v1/password", strings.NewReader(`{"current":"`+testPassword+`","new":"another long password"}`), hdr)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("change: %d %s", resp.StatusCode, readBody(t, resp))
	}
	hash, _ := env.st.PasswordHash(auth.User)
	if !auth.VerifyPassword(hash, "another long password") {
		t.Error("the new password is stored")
	}
}

func TestThemeAndMenu(t *testing.T) {
	env := newEnv(t, nil)
	env.login()
	get := func(path, cookie string) (*http.Response, string) {
		t.Helper()
		hdr := map[string]string{}
		if cookie != "" {
			hdr["Cookie"] = cookie
		}
		resp := env.do("GET", path, nil, hdr)
		return resp, readBody(t, resp)
	}
	themeCookie := func(resp *http.Response) *http.Cookie {
		for _, c := range resp.Cookies() {
			if c.Name == "theme" {
				return c
			}
		}
		return nil
	}

	// Without a choice, the computer's setting.
	_, page := get("/settings", "")
	if strings.Contains(page, "data-theme=") || strings.Contains(page, `data-nav="hidden"`) {
		t.Error("no theme or hidden menu by default")
	}
	mustContain(t, page, `data-theme-set="system" class="on"`, "same as the computer", `aria-expanded="true"`)

	// ?theme= works without the page script, and is remembered.
	resp, page := get("/settings?theme=dark", "")
	if c := themeCookie(resp); c == nil || c.Value != "dark" || !c.Secure || c.MaxAge <= 0 {
		t.Errorf("theme cookie: %+v", c)
	}
	mustContain(t, page, `<html lang="en" data-mode="basic" data-theme="dark"`, `data-theme-set="dark" class="on"`)
	_, page = get("/", "theme=light")
	mustContain(t, page, `data-theme="light"`)
	resp, page = get("/settings?theme=system", "theme=light")
	if c := themeCookie(resp); c == nil || c.MaxAge >= 0 || strings.Contains(page, "data-theme=") {
		t.Errorf("back to the computer's setting: %+v", c)
	}
	if _, page = get("/", "theme=blue"); strings.Contains(page, "data-theme=") {
		t.Error("an unknown theme is ignored")
	}

	// The hidden menu.
	_, page = get("/settings", "nav=hidden")
	mustContain(t, page, `data-nav="hidden"`, `aria-expanded="false"`, "Menu on the left</dt><dd>hidden")

	// The sign-in page follows the theme too.
	env.cookie = nil
	resp, page = get("/login", "theme=dark")
	if resp.StatusCode != 200 || !strings.Contains(page, `data-theme="dark"`) {
		t.Errorf("the sign-in page follows the theme: %d", resp.StatusCode)
	}
}

func mustAtoi(t *testing.T, s string) int {
	t.Helper()
	n, err := strconv.Atoi(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}
