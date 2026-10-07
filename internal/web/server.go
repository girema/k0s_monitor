// Package web serves the UI, the JSON API and the live update stream
// (plan sections 11 and 12). Pages are rendered on the server; a small
// script adds live updates, the mode switch and notifications.
package web

import (
	"context"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"k0s_monitor/internal/account"
	"k0s_monitor/internal/auth"
	"k0s_monitor/internal/config"
	"k0s_monitor/internal/conntest"
	"k0s_monitor/internal/engine"
	"k0s_monitor/internal/pack"
	"k0s_monitor/internal/store"
)

//go:embed templates static
var assets embed.FS

// Options configure the server.
type Options struct {
	Config *config.Config
	Fleet  *engine.Fleet
	Store  *store.Store
	// NoAuth turns sign-in off. It is only allowed when the UI listens on
	// a loopback address (laptop mode).
	NoAuth bool
	// Host is shown in the sidebar, for example "jump-01".
	Host string
	// URL is where the UI can be opened, for the sidebar.
	URL string
	// CertExpires is when the server certificate expires, to warn early.
	CertExpires time.Time
	// CanStoreClusters is false when there is no key to encrypt the
	// credentials of clusters added in the UI.
	CanStoreClusters bool
	Logger           *slog.Logger
	Now              func() time.Time
	// Packs are the product packs; nil for none.
	Packs *pack.Registry

	// For tests: replace the connection test, the account creation and the
	// access check of the Add cluster page.
	TestConnection func(context.Context, config.Cluster, conntest.Options) *conntest.Report
	CreateAccount  func(context.Context, config.Cluster, account.Options) (*account.Result, error)
	VerifyAccess   func(context.Context, config.Cluster) error
}

// Server is the web server.
type Server struct {
	o        Options
	mux      *http.ServeMux
	sessions *auth.Sessions
	limiter  *auth.Limiter
	// argon bounds the password hashes computed at once.
	argon *auth.Gate
	// metricsToken lets a scraper read /metrics; empty when not set.
	metricsToken string
	allow        *auth.AllowList
	hub          *hub
	notify       *notifier
	pages        map[string]*template.Template
	log          *slog.Logger
	now          func() time.Time
	// implicit is the session used in NoAuth mode.
	implicit *auth.Session

	draftsMu sync.Mutex
	drafts   map[string]*draft

	// reports are the prepared reports for support, by ID.
	reportsMu sync.Mutex
	reports   map[string]*preparedReport

	// ai remembers the AI explanations and bounds the requests.
	ai *aiState
	// mutes caches the hidden alerts.
	mutes muteCache
}

// argonSlots is how many password hashes may run at once: 4 × 64 MiB.
const argonSlots = 4

type ctxKey int

const sessionKey ctxKey = 1

// New creates the server. Call OnEvent from the engines' event callback.
func New(o Options) (*Server, error) {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	al, err := auth.NewAllowList(o.Config.AllowFrom)
	if err != nil {
		return nil, err
	}
	s := &Server{
		o:        o,
		mux:      http.NewServeMux(),
		sessions: auth.NewSessions(o.Config.Auth.SessionIdle.D(), o.Config.Auth.SessionMax.D()),
		argon:    auth.NewGate(argonSlots, 2*time.Second),
		limiter:  auth.NewLimiter(),
		allow:    al,
		hub:      newHub(),
		log:      o.Logger,
		now:      o.Now,
		drafts:   map[string]*draft{},
		reports:  map[string]*preparedReport{},
		ai:       newAIState(),
	}
	if f := o.Config.MetricsTokenFile; f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("metricsTokenFile: %w", err)
		}
		if s.metricsToken = strings.TrimSpace(string(b)); len(s.metricsToken) < 16 {
			return nil, fmt.Errorf("metricsTokenFile %s: the token must have at least 16 characters", f)
		}
	}
	s.notify = newNotifier(o.Store, s.hub, o.Config.UI.Notify)
	if o.NoAuth {
		s.implicit = s.sessions.Create(auth.User, "local")
	}
	if err := s.parseTemplates(); err != nil {
		return nil, err
	}
	s.routes()
	return s, nil
}

// OnEvent receives engine events: it records notifications and pushes
// updates to browsers.
func (s *Server) OnEvent(ev engine.Event) {
	s.notify.handle(ev)
	switch ev.Type {
	case engine.StateChanged, engine.ClusterConnected, engine.ClusterDisconnected:
		s.hub.publish("state", ev.Cluster, map[string]string{"cluster": ev.Cluster, "type": string(ev.Type)})
	case engine.FindingOpened, engine.FindingUpdated, engine.FindingResolved:
		s.hub.publish(string(ev.Type), ev.Cluster, ev)
	}
}

// Handler returns the HTTP handler with all middleware.
func (s *Server) Handler() http.Handler {
	return s.secure(s.mux)
}

func (s *Server) routes() {
	static, _ := fs.Sub(assets, "static")
	s.mux.Handle("GET /static/", http.StripPrefix("/static/", cacheStatic(http.FileServerFS(static))))
	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok\n")) })
	s.mux.HandleFunc("GET /metrics", s.metricsAccess(s.metrics))

	// Sign-in.
	s.mux.HandleFunc("GET /login", s.loginPage)
	s.mux.HandleFunc("POST /login", s.loginForm)
	s.mux.HandleFunc("POST /logout", s.signedIn(s.logout))
	s.mux.HandleFunc("POST /api/v1/session", s.apiLogin)
	s.mux.HandleFunc("DELETE /api/v1/session", s.signedIn(s.apiLogout))

	// Pages.
	s.mux.HandleFunc("GET /{$}", s.signedIn(s.clustersPage))
	s.mux.HandleFunc("GET /clusters/add", s.signedIn(s.addClusterPage))
	s.mux.HandleFunc("GET /c/{cluster}", s.signedIn(s.overviewPage))
	s.mux.HandleFunc("GET /c/{cluster}/problems", s.signedIn(s.problemsPage))
	s.mux.HandleFunc("GET /c/{cluster}/problems/{id}", s.signedIn(s.findingPage))
	s.mux.HandleFunc("GET /c/{cluster}/alerts", s.signedIn(s.alertsPage))
	s.mux.HandleFunc("POST /c/{cluster}/alerts", s.signedIn(s.alertsForm))
	s.mux.HandleFunc("GET /c/{cluster}/pods/{ns}/{name}", s.signedIn(s.podPage))
	s.mux.HandleFunc("GET /c/{cluster}/apps", s.signedIn(s.appsPage))
	s.mux.HandleFunc("GET /c/{cluster}/secrets", s.signedIn(s.secretsPage))
	s.mux.HandleFunc("GET /c/{cluster}/secrets/{ns}/{name}", s.signedIn(s.secretPage))
	s.mux.HandleFunc("GET /c/{cluster}/servers", s.signedIn(s.serversPage))
	s.mux.HandleFunc("GET /c/{cluster}/servers/add", s.signedIn(s.addNodePage))
	s.mux.HandleFunc("GET /c/{cluster}/storage", s.signedIn(s.storagePage))
	s.mux.HandleFunc("GET /c/{cluster}/k0s", s.signedIn(s.k0sPage))
	s.mux.HandleFunc("GET /c/{cluster}/report", s.signedIn(s.reportPage))
	s.mux.HandleFunc("POST /c/{cluster}/report", s.signedIn(s.reportForm))
	s.mux.HandleFunc("GET /c/{cluster}/report/{id}/download", s.signedIn(s.reportDownload))
	s.mux.HandleFunc("GET /c/{cluster}/report/{id}/files/{path...}", s.signedIn(s.reportFile))
	s.mux.HandleFunc("GET /c/{cluster}/settings", s.signedIn(s.clusterSettingsPage))
	s.mux.HandleFunc("POST /c/{cluster}/settings/metrics", s.signedIn(s.clusterMetricsForm))
	s.mux.HandleFunc("POST /c/{cluster}/settings/k0s", s.signedIn(s.clusterK0sForm))
	s.mux.HandleFunc("POST /c/{cluster}/settings/account", s.signedIn(s.clusterAccountForm))
	s.mux.HandleFunc("POST /c/{cluster}/settings/tls", s.signedIn(s.clusterTLSForm))
	s.mux.HandleFunc("GET /settings", s.signedIn(s.settingsPage))
	s.mux.HandleFunc("GET /glossary", s.signedIn(s.glossaryPage))
	s.mux.HandleFunc("POST /settings/password", s.signedIn(s.passwordForm))
	s.mux.HandleFunc("POST /settings/secrets", s.signedIn(s.secretValuesForm))
	s.mux.HandleFunc("POST /settings/ai", s.signedIn(s.aiSettingsForm))
	s.mux.HandleFunc("POST /settings/packs", limitBody(packUploadLimit, s.signedIn(s.packUploadForm)))
	s.mux.HandleFunc("POST /settings/packs/reload", s.signedIn(s.packReloadForm))
	s.mux.HandleFunc("POST /settings/packs/{name}/remove", s.signedIn(s.packRemoveForm))
	s.mux.HandleFunc("GET /settings/packs/{file}", s.signedIn(s.packFile))
	s.mux.HandleFunc("POST /settings/users", s.signedIn(s.addUserForm))
	s.mux.HandleFunc("POST /settings/users/{name}/password", s.signedIn(s.userPasswordForm))
	s.mux.HandleFunc("POST /settings/users/{name}/remove", s.signedIn(s.removeUserForm))
	s.mux.HandleFunc("POST /c/{cluster}/problems/{id}/state", s.signedIn(s.findingStateForm))

	// JSON API (plan section 12).
	s.mux.HandleFunc("GET /api/v1/clusters", s.signedIn(s.apiClusters))
	s.mux.HandleFunc("POST /api/v1/clusters/import", s.signedIn(s.apiImport))
	s.mux.HandleFunc("POST /api/v1/clusters/test", s.signedIn(s.apiTest))
	s.mux.HandleFunc("POST /api/v1/clusters", s.signedIn(s.apiAddCluster))
	s.mux.HandleFunc("DELETE /api/v1/clusters/{cluster}", s.signedIn(s.apiDeleteCluster))
	s.mux.HandleFunc("POST /api/v1/clusters/{cluster}/retry", s.signedIn(s.apiRetry))
	s.mux.HandleFunc("GET /api/v1/clusters/{cluster}/health", s.signedIn(s.apiHealth))
	s.mux.HandleFunc("GET /api/v1/clusters/{cluster}/findings", s.signedIn(s.apiFindings))
	s.mux.HandleFunc("GET /api/v1/clusters/{cluster}/findings/{id}", s.signedIn(s.apiFinding))
	s.mux.HandleFunc("GET /api/v1/clusters/{cluster}/alerts", s.signedIn(s.apiAlerts))
	s.mux.HandleFunc("POST /api/v1/clusters/{cluster}/alerts/hide", s.signedIn(s.apiHideAlerts))
	s.mux.HandleFunc("POST /api/v1/clusters/{cluster}/alerts/show", s.signedIn(s.apiShowAlerts))
	s.mux.HandleFunc("GET /api/v1/clusters/{cluster}/findings/{id}/explain", s.signedIn(s.apiExplainPreview))
	s.mux.HandleFunc("POST /api/v1/clusters/{cluster}/findings/{id}/explain", s.signedIn(s.apiExplain))
	s.mux.HandleFunc("GET /api/v1/settings/ai", s.signedIn(s.apiGetAI))
	s.mux.HandleFunc("PUT /api/v1/settings/ai", s.signedIn(s.apiPutAI))
	s.mux.HandleFunc("POST /api/v1/settings/ai/test", s.signedIn(s.apiTestAI))
	s.mux.HandleFunc("POST /api/v1/clusters/{cluster}/findings/{id}/ack", s.signedIn(s.apiAck))
	s.mux.HandleFunc("POST /api/v1/clusters/{cluster}/findings/{id}/snooze", s.signedIn(s.apiSnooze))
	s.mux.HandleFunc("POST /api/v1/clusters/{cluster}/findings/{id}/reopen", s.signedIn(s.apiReopen))
	s.mux.HandleFunc("GET /api/v1/clusters/{cluster}/pods/{ns}/{name}", s.signedIn(s.apiPod))
	s.mux.HandleFunc("GET /api/v1/clusters/{cluster}/pods/{ns}/{name}/describe", s.signedIn(s.apiPodDescribe))
	s.mux.HandleFunc("GET /api/v1/clusters/{cluster}/pods/{ns}/{name}/events", s.signedIn(s.apiPodEvents))
	s.mux.HandleFunc("GET /api/v1/clusters/{cluster}/pods/{ns}/{name}/yaml", s.signedIn(s.apiPodYAML))
	s.mux.HandleFunc("GET /api/v1/clusters/{cluster}/pods/{ns}/{name}/logs", s.signedIn(s.apiPodLogs))
	s.mux.HandleFunc("POST /api/v1/clusters/{cluster}/secrets/{ns}/{name}/reveal", s.signedIn(s.apiSecretReveal))
	s.mux.HandleFunc("GET /api/v1/clusters/{cluster}/report", s.signedIn(s.apiReport))
	s.mux.HandleFunc("GET /api/v1/notifications", s.signedIn(s.apiNotifications))
	s.mux.HandleFunc("POST /api/v1/notifications/read", s.signedIn(s.apiNotificationsRead))
	s.mux.HandleFunc("GET /api/v1/audit", s.signedIn(s.apiAudit))
	s.mux.HandleFunc("GET /api/v1/packs", s.signedIn(s.apiPacks))
	s.mux.HandleFunc("POST /api/v1/packs", limitBody(pack.MaxSize, s.signedIn(s.apiUploadPack)))
	s.mux.HandleFunc("DELETE /api/v1/packs/{name}", s.signedIn(s.apiRemovePack))
	s.mux.HandleFunc("GET /api/v1/settings", s.signedIn(s.apiSettings))
	s.mux.HandleFunc("PATCH /api/v1/settings", s.signedIn(s.apiPatchSettings))
	s.mux.HandleFunc("POST /api/v1/password", s.signedIn(s.apiPassword))
	s.mux.HandleFunc("GET /api/v1/users", s.signedIn(s.apiUsers))
	s.mux.HandleFunc("POST /api/v1/users", s.signedIn(s.apiAddUser))
	s.mux.HandleFunc("PUT /api/v1/users/{name}/password", s.signedIn(s.apiUserPassword))
	s.mux.HandleFunc("DELETE /api/v1/users/{name}", s.signedIn(s.apiRemoveUser))
	s.mux.HandleFunc("GET /api/v1/stream", s.signedIn(s.stream))
}

// ---------------------------------------------------------------------------
// Middleware

// secure adds the security headers, enforces the allow-list and, in
// NoAuth mode, accepts only loopback host names (against DNS rebinding).
func (s *Server) secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "+
			"connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		// same-origin, not no-referrer: with no-referrer, browsers send
		// "Origin: null" on the page's own form posts and fetches, and
		// sameOrigin would refuse them.
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		if r.TLS != nil {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		ip := clientIP(r)
		if !s.allow.Allowed(ip) {
			s.log.Warn("request refused by allowFrom", "ip", ip, "path", r.URL.Path)
			http.Error(w, "This address may not open k0s-monitor (allowFrom).", http.StatusForbidden)
			return
		}
		if s.o.NoAuth && !loopbackHost(r.Host) {
			http.Error(w, "Without sign-in, k0s-monitor only answers on localhost.", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// sessionFor returns the request's live session, or nil.
func (s *Server) sessionFor(r *http.Request) *auth.Session {
	if s.implicit != nil {
		return s.implicit
	}
	if c, err := r.Cookie(sessionCookie); err == nil {
		if got, ok := s.sessions.Get(c.Value); ok {
			return got
		}
	}
	return nil
}

// metricsAccess lets a signed-in session read /metrics, or a scraper that
// sends the token from metricsTokenFile.
func (s *Server) metricsAccess(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok && s.metricsToken != "" &&
			subtle.ConstantTimeCompare([]byte(token), []byte(s.metricsToken)) == 1 {
			h(w, r)
			return
		}
		if s.sessionFor(r) == nil {
			w.Header().Set("WWW-Authenticate", `Bearer realm="k0s-monitor"`)
			http.Error(w, "Sign in, or send the token of metricsTokenFile.", http.StatusUnauthorized)
			return
		}
		h(w, r)
	}
}

// signedIn requires a session and, for requests that change something, a
// valid CSRF token.
func (s *Server) signedIn(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := s.sessionFor(r)
		if sess == nil {
			if isAPI(r) {
				writeError(w, http.StatusUnauthorized, "sign in first")
				return
			}
			http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			token := r.Header.Get("X-CSRF-Token")
			if token == "" {
				token = r.PostFormValue("csrf")
			}
			if token == "" || subtle.ConstantTimeCompare([]byte(token), []byte(sess.CSRF)) != 1 || !sameOrigin(r) {
				if isAPI(r) {
					writeError(w, http.StatusForbidden, "missing or wrong CSRF token")
				} else {
					http.Error(w, "The form expired. Go back, reload the page and try again.", http.StatusForbidden)
				}
				return
			}
		}
		h(w, r.WithContext(context.WithValue(r.Context(), sessionKey, sess)))
	}
}

func randomToken() string { return auth.RandomToken() }

func sessionOf(r *http.Request) *auth.Session {
	sess, _ := r.Context().Value(sessionKey).(*auth.Session)
	return sess
}

// sameOrigin rejects cross-site requests. Browsers say where a request
// comes from in Sec-Fetch-Site, which also holds behind a proxy that
// rewrites the host. Without it (older browsers), Origin must match the
// host when it is sent; "Origin: null" is refused. Clients that send
// neither, such as curl, are not browsers and can't be tricked into it.
func sameOrigin(r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "same-origin":
		return true
	case "same-site", "cross-site":
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	return err == nil && u.Host != "" && strings.EqualFold(u.Host, r.Host)
}

func isAPI(r *http.Request) bool { return strings.HasPrefix(r.URL.Path, "/api/") }

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func loopbackHost(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func cacheStatic(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=300")
		h.ServeHTTP(w, r)
	})
}

// ---------------------------------------------------------------------------
// Helpers

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

type apiError struct {
	Error string `json:"error"`
	Hint  string `json:"hint,omitempty"`
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, apiError{Error: msg})
}

func readJSON(r *http.Request, v any, limit int64) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, limit))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return fmt.Errorf("the request is larger than %d KiB", limit/1024)
		}
		return fmt.Errorf("invalid request: %w", err)
	}
	return nil
}

func (s *Server) engineOf(w http.ResponseWriter, r *http.Request) *engine.Engine {
	name := r.PathValue("cluster")
	e := s.o.Fleet.Get(name)
	if e == nil {
		if isAPI(r) {
			writeError(w, http.StatusNotFound, fmt.Sprintf("no cluster named %q", name))
		} else {
			s.notFound(w, r, fmt.Sprintf("There is no cluster named %q.", name))
		}
	}
	return e
}

func (s *Server) audit(r *http.Request, action, detail string) {
	user := auth.User
	if sess := sessionOf(r); sess != nil {
		user = sess.User
	}
	if err := s.o.Store.Audit(user, clientIP(r), action, detail); err != nil {
		s.log.Error("writing the audit log", "err", err)
	}
}
