package web

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"k0s_monitor/internal/cluster"
	"k0s_monitor/internal/engine"
	"k0s_monitor/internal/findings"
	"k0s_monitor/internal/priority"
	"k0s_monitor/internal/store"
)

type apiTop struct {
	ID         string            `json:"id"`
	Priority   findings.Priority `json:"priority"`
	Title      string            `json:"title"`
	PlainTitle string            `json:"plainTitle"`
}

type apiCluster struct {
	Name   string        `json:"name"`
	Status engine.Status `json:"status"`
	Server string        `json:"server,omitempty"`
	// Fallback is set while Server is another controller than the
	// kubeconfig's, which doesn't answer.
	Fallback         *cluster.Fallback         `json:"fallback,omitempty"`
	Version          string                    `json:"version,omitempty"`
	K0s              bool                      `json:"k0s"`
	Nodes            int                       `json:"nodes"`
	Pods             int                       `json:"pods"`
	Health           *priority.Health          `json:"health,omitempty"`
	HealthAt         *time.Time                `json:"healthAt,omitempty"`
	Counts           map[findings.Priority]int `json:"counts"`
	Symptoms         int                       `json:"foldedSymptoms"`
	TopIssue         *apiTop                   `json:"topIssue,omitempty"`
	Error            *cluster.ConnError        `json:"error,omitempty"`
	Warnings         []string                  `json:"warnings,omitempty"`
	LastSync         *time.Time                `json:"lastSync,omitempty"`
	UnreachableSince *time.Time                `json:"unreachableSince,omitempty"`
	RetryAt          *time.Time                `json:"retryAt,omitempty"`
	AddedInUI        bool                      `json:"addedInUi"`
	// Suggestions counts the good-practice findings, which Counts leaves
	// out.
	Suggestions int `json:"suggestions"`
}

func apiClusterOf(e *engine.Engine) apiCluster {
	st := e.State()
	c := apiCluster{Name: st.Name, Status: st.Status, Health: st.Health, HealthAt: st.HealthAt, Counts: st.Counts,
		Symptoms: st.Symptoms, Error: st.Error, Warnings: st.Warnings, LastSync: st.LastSync,
		UnreachableSince: st.UnreachableSince, RetryAt: st.RetryAt, AddedInUI: e.Cluster().FromUI, Suggestions: st.Suggestions}
	if st.Info != nil {
		c.Server, c.Version, c.K0s, c.Nodes, c.Pods = st.Info.Server, st.Info.Version, st.Info.K0s, st.Info.Nodes, st.Info.Pods
		c.Fallback = st.Info.Fallback
	}
	if f := topRoot(st); f != nil {
		c.TopIssue = &apiTop{ID: f.ID, Priority: f.Priority, Title: f.Title, PlainTitle: f.Plain.Title}
	}
	return c
}

func (s *Server) apiClusters(w http.ResponseWriter, _ *http.Request) {
	out := []apiCluster{}
	for _, e := range s.o.Fleet.Engines() {
		out = append(out, apiClusterOf(e))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) apiHealth(w http.ResponseWriter, r *http.Request) {
	e := s.engineOf(w, r)
	if e == nil {
		return
	}
	st := e.State()
	writeJSON(w, http.StatusOK, map[string]any{
		"cluster": st.Name, "status": st.Status, "health": st.Health, "healthAt": st.HealthAt,
		"info": st.Info, "warnings": st.Warnings, "skippedRules": st.Skipped,
	})
}

// apiFindings lists findings in display order. Filters: priority,
// category, namespace, node, symptoms=false (roots only), state=all
// (include acknowledged and snoozed; the default hides nothing).
func (s *Server) apiFindings(w http.ResponseWriter, r *http.Request) {
	e := s.engineOf(w, r)
	if e == nil {
		return
	}
	q := r.URL.Query()
	out := []*findings.Finding{}
	for _, f := range e.State().Findings {
		if p := q.Get("priority"); p != "" && !strings.EqualFold(string(f.Priority), p) {
			continue
		}
		if c := q.Get("category"); c != "" && string(f.Category) != c {
			continue
		}
		if ns := q.Get("namespace"); ns != "" && f.Resource.Namespace != ns {
			continue
		}
		if n := q.Get("node"); n != "" && !(f.Resource.Kind == "Node" && f.Resource.Name == n) && !contains(f.Links.Nodes, n) {
			continue
		}
		if q.Get("symptoms") == "false" && f.IsSymptom() {
			continue
		}
		out = append(out, f)
	}
	writeJSON(w, http.StatusOK, out)
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func (s *Server) apiFinding(w http.ResponseWriter, r *http.Request) {
	e := s.engineOf(w, r)
	if e == nil {
		return
	}
	id := r.PathValue("id")
	f := e.State().Finding(id)
	history, _ := s.o.Store.History(e.Name(), id)
	if f == nil && len(history) == 0 {
		writeError(w, http.StatusNotFound, "no such finding")
		return
	}
	var symptoms []*findings.Finding
	if f != nil {
		for _, c := range e.State().Findings {
			if c.ParentID == f.ID {
				symptoms = append(symptoms, c)
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"finding": f, "symptoms": symptoms, "history": history})
}

var errNoFinding = errors.New("this problem is no longer open")

// setFindingState acknowledges, snoozes or reopens a finding.
func (s *Server) setFindingState(r *http.Request, e *engine.Engine, id, action string, until *time.Time) error {
	f := e.State().Finding(id)
	if f == nil {
		return errNoFinding
	}
	var err error
	switch action {
	case "ack":
		err = s.o.Store.SetUserState(e.Name(), id, engine.UserState{State: findings.StateAcknowledged, Priority: f.Priority, By: sessionOf(r).User})
	case "snooze":
		if until == nil || !until.After(s.now()) {
			return errors.New("a snooze needs an end in the future")
		}
		err = s.o.Store.SetUserState(e.Name(), id, engine.UserState{State: findings.StateSnoozed, Until: until, Priority: f.Priority, By: sessionOf(r).User})
	case "reopen":
		err = s.o.Store.ClearUserState(e.Name(), id)
	default:
		return fmt.Errorf("unknown action %q", action)
	}
	if err != nil {
		return err
	}
	detail := e.Name() + " " + f.RuleID + " " + f.Resource.String()
	if until != nil {
		detail += " until " + until.UTC().Format(time.RFC3339)
	}
	s.audit(r, "finding."+action, detail)
	e.RefreshAndWait(2 * time.Second)
	return nil
}

func (s *Server) apiAck(w http.ResponseWriter, r *http.Request) {
	s.apiState(w, r, "ack", nil)
}

func (s *Server) apiReopen(w http.ResponseWriter, r *http.Request) {
	s.apiState(w, r, "reopen", nil)
}

type snoozeRequest struct {
	// Until is an RFC 3339 time, or Duration a Go duration such as "4h".
	Until    *time.Time `json:"until,omitempty"`
	Duration string     `json:"duration,omitempty"`
}

func (s *Server) apiSnooze(w http.ResponseWriter, r *http.Request) {
	var req snoozeRequest
	if err := readJSON(r, &req, 4<<10); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	until := req.Until
	if until == nil {
		d, err := time.ParseDuration(req.Duration)
		if err != nil || d <= 0 {
			writeError(w, http.StatusBadRequest, "give until (RFC 3339) or a positive duration such as \"4h\"")
			return
		}
		t := s.now().Add(d)
		until = &t
	}
	s.apiState(w, r, "snooze", until)
}

func (s *Server) apiState(w http.ResponseWriter, r *http.Request, action string, until *time.Time) {
	e := s.engineOf(w, r)
	if e == nil {
		return
	}
	id := r.PathValue("id")
	if err := s.setFindingState(r, e, id, action, until); err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, errNoFinding) {
			status = http.StatusNotFound
		}
		writeError(w, status, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"finding": e.State().Finding(id)})
}

func (s *Server) apiRetry(w http.ResponseWriter, r *http.Request) {
	e := s.engineOf(w, r)
	if e == nil {
		return
	}
	e.RetryNow()
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) apiNotifications(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 && v <= 500 {
		limit = v
	}
	ns, unread, err := s.o.Store.Notifications(sessionOf(r).User, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if ns == nil {
		ns = []store.Notification{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"notifications": ns, "unread": unread})
}

type readRequest struct {
	// UpTo marks notifications up to this sequence number as read; 0 marks all.
	UpTo int64 `json:"upTo"`
}

func (s *Server) apiNotificationsRead(w http.ResponseWriter, r *http.Request) {
	var req readRequest
	if r.ContentLength != 0 {
		if err := readJSON(r, &req, 1<<10); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	user := sessionOf(r).User
	if err := s.o.Store.MarkRead(user, req.UpTo); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_, unread, _ := s.o.Store.Notifications(user, 0)
	// The user's other tabs update their bell; other users' stay as is.
	s.hub.publishTo(user, "unread", map[string]int{"unread": unread})
	writeJSON(w, http.StatusOK, map[string]int{"unread": unread})
}

func (s *Server) apiAudit(w http.ResponseWriter, _ *http.Request) {
	log, err := s.o.Store.AuditLog(500)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, log)
}

type settingsResponse struct {
	DefaultMode string   `json:"defaultMode"`
	Notify      []string `json:"notify"`
	SignIn      bool     `json:"signIn"`
	// SecretValues is true while Secret values may be shown, one at a
	// time.
	SecretValues bool `json:"secretValues"`
}

func (s *Server) settingsNow() settingsResponse {
	mode := s.o.Config.UI.DefaultMode
	if v, _ := s.o.Store.Setting("ui.defaultMode"); v != "" {
		mode = v
	}
	return settingsResponse{DefaultMode: mode, Notify: s.o.Config.UI.Notify, SignIn: !s.o.NoAuth, SecretValues: s.secretValuesOn()}
}

func (s *Server) apiSettings(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.settingsNow())
}

type settingsPatch struct {
	DefaultMode  *string `json:"defaultMode,omitempty"`
	SecretValues *bool   `json:"secretValues,omitempty"`
}

func (s *Server) apiPatchSettings(w http.ResponseWriter, r *http.Request) {
	var req settingsPatch
	if err := readJSON(r, &req, 4<<10); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.DefaultMode != nil {
		if *req.DefaultMode != "basic" && *req.DefaultMode != "full" {
			writeError(w, http.StatusBadRequest, "defaultMode must be basic or full")
			return
		}
		if err := s.o.Store.SetSetting("ui.defaultMode", *req.DefaultMode); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.audit(r, "settings.change", "defaultMode="+*req.DefaultMode)
	}
	if req.SecretValues != nil && *req.SecretValues != s.secretValuesOn() {
		if err := s.setSecretValues(r, *req.SecretValues); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	writeJSON(w, http.StatusOK, s.settingsNow())
}

// stream sends live updates as server-sent events.
func (s *Server) stream(w http.ResponseWriter, r *http.Request) {
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{})
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Accel-Buffering", "no")
	sess := sessionOf(r)
	ch := s.hub.subscribe(sess.User)
	defer s.hub.unsubscribe(ch)
	fmt.Fprint(w, "retry: 5000\n\n")
	if err := rc.Flush(); err != nil {
		return
	}
	ping := time.NewTicker(25 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case m := <-ch:
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", m.Event, m.Data)
		case <-ping.C:
			if sess != s.implicit && !s.sessions.Alive(sess.ID) {
				return
			}
			fmt.Fprint(w, ": ping\n\n")
		}
		if err := rc.Flush(); err != nil {
			return
		}
	}
}

// metrics exposes a few numbers about the tool in the Prometheus format.
func (s *Server) metrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintln(w, "# HELP k0s_monitor_findings Open root causes by cluster and priority.")
	fmt.Fprintln(w, "# TYPE k0s_monitor_findings gauge")
	for _, e := range s.o.Fleet.Engines() {
		st := e.State()
		for _, p := range []findings.Priority{findings.P1, findings.P2, findings.P3, findings.P4} {
			fmt.Fprintf(w, "k0s_monitor_findings{cluster=%q,priority=%q} %d\n", st.Name, p, st.Counts[p])
		}
	}
	fmt.Fprintln(w, "# HELP k0s_monitor_cluster_up Whether the cluster can be reached (1) or not (0).")
	fmt.Fprintln(w, "# TYPE k0s_monitor_cluster_up gauge")
	for _, e := range s.o.Fleet.Engines() {
		st := e.State()
		up := 0
		if st.Status == engine.StatusOK || st.Status == engine.StatusPartial {
			up = 1
		}
		fmt.Fprintf(w, "k0s_monitor_cluster_up{cluster=%q} %d\n", st.Name, up)
		if st.Health != nil {
			fmt.Fprintf(w, "k0s_monitor_health_score{cluster=%q} %d\n", st.Name, st.Health.Score)
		}
	}
	fmt.Fprintf(w, "k0s_monitor_stream_clients %d\n", s.hub.count())
}
