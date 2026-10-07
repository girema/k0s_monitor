package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"k0s_monitor/internal/alerts"
	"k0s_monitor/internal/engine"
	"k0s_monitor/internal/findings"
	"k0s_monitor/internal/snapshot"
	"k0s_monitor/internal/store"
)

// The alerts that fire in a cluster's Prometheus (M5), each linked to the
// problems k0s-monitor found about the same object, grouped by name. People
// can hide an alert here, everywhere in the cluster or on one server; that
// never changes Prometheus or its Alertmanager.

type alertRow struct {
	snapshot.Alert
	ID    string
	About findings.ObjectRef
	// Server is the node or controller it is about, if any: what hiding
	// "on this server" means.
	Server string
	// Problems are the root problems the alert is about.
	Problems []*findings.Finding
	// Mute hides it, when it is hidden.
	Mute *store.AlertMute
	// Detail tells it from the others of its name: the labels whose
	// values differ, such as "device sdc".
	Detail string
}

// alertGroup is the alerts of one name.
type alertGroup struct {
	Name, Severity, Text string
	// Rows are the ones shown; Hidden counts the others.
	Rows   []alertRow
	Hidden int
	// Servers counts the servers the shown ones are about.
	Servers int
	// Since is when the longest firing one started.
	Since  time.Time
	Linked int
}

type alertsData struct {
	State *engine.State
	// Read says the alerts could be read; From how ("alerts API" or
	// "ALERTS series") and Source from which Prometheus.
	Read         bool
	From, Source string
	// Rows are every firing alert, Groups the shown ones by name.
	Rows   []alertRow
	Groups []alertGroup
	// Shown, Linked and Hidden count alerts: shown, shown and linked to a
	// problem, and hidden.
	Shown, Linked, Hidden int
	// Mutes are the hidings that are in force.
	Mutes []muteRow
}

// muteRow is a hiding, with how many alerts it hides now.
type muteRow struct {
	store.AlertMute
	Hides int
}

// alertsOf lists the firing alerts with the problems they are about,
// hiding those the mutes say.
func alertsOf(st *engine.State, mutes []store.AlertMute, now time.Time) (d alertsData) {
	d = alertsData{State: st}
	active := activeMutes(mutes, now)
	hides := make([]int, len(active))
	defer func() {
		for i, mu := range active {
			d.Mutes = append(d.Mutes, muteRow{AlertMute: mu, Hides: hides[i]})
		}
	}()
	if st.Snapshot == nil || st.Snapshot.Metrics == nil || !st.Snapshot.Metrics.AlertsRead {
		return d
	}
	m := st.Snapshot.Metrics
	d.Read, d.From, d.Source = true, m.AlertsFrom, m.Source
	// The problems each alert reached, as their roots.
	byAlert := map[string][]*findings.Finding{}
	seen := map[string]bool{}
	for _, f := range st.Findings {
		root := f
		if f.IsSymptom() {
			if p := st.Finding(f.ParentID); p != nil {
				root = p
			}
		}
		for _, a := range f.Alerts {
			if key := a.ID + "/" + root.ID; !seen[key] {
				seen[key] = true
				byAlert[a.ID] = append(byAlert[a.ID], root)
			}
		}
	}
	groups := map[string]*alertGroup{}
	var order []string
	servers := map[string]map[string]bool{}
	for _, a := range m.Alerts {
		row := alertRow{Alert: a, ID: a.ID(), Problems: byAlert[a.ID()]}
		if objs := alerts.Objects(a, st.Snapshot); len(objs) > 0 {
			row.About = objs[0]
		}
		row.Server = serverOf(row.About)
		if i := muteFor(active, a.Name, row.Server); i >= 0 {
			row.Mute = &active[i]
			hides[i]++
		}
		d.Rows = append(d.Rows, row)
		g := groups[a.Name]
		if g == nil {
			g = &alertGroup{Name: a.Name, Severity: a.Severity, Text: a.Text()}
			groups[a.Name] = g
			order = append(order, a.Name)
			servers[a.Name] = map[string]bool{}
		}
		if row.Mute != nil {
			g.Hidden++
			d.Hidden++
			continue
		}
		g.Rows = append(g.Rows, row)
		d.Shown++
		if snapshot.SeverityRank(a.Severity) < snapshot.SeverityRank(g.Severity) {
			g.Severity = a.Severity
		}
		if !a.Since.IsZero() && (g.Since.IsZero() || a.Since.Before(g.Since)) {
			g.Since = a.Since
		}
		if row.Server != "" {
			servers[a.Name][row.Server] = true
		}
		if len(row.Problems) > 0 {
			g.Linked++
			d.Linked++
		}
	}
	for _, name := range order {
		g := groups[name]
		g.Servers = len(servers[name])
		if len(g.Rows) == 0 {
			continue
		}
		details(g.Rows)
		sort.SliceStable(g.Rows, func(i, j int) bool {
			if g.Rows[i].Server != g.Rows[j].Server {
				return g.Rows[i].Server < g.Rows[j].Server
			}
			return g.Rows[i].Detail < g.Rows[j].Detail
		})
		d.Groups = append(d.Groups, *g)
	}
	// Most severe first, then the most alerts.
	sort.SliceStable(d.Groups, func(i, j int) bool {
		ri, rj := snapshot.SeverityRank(d.Groups[i].Severity), snapshot.SeverityRank(d.Groups[j].Severity)
		if ri != rj {
			return ri < rj
		}
		return len(d.Groups[i].Rows) > len(d.Groups[j].Rows)
	})
	return d
}

// details sets each row's Detail: the shown labels whose values differ
// between the rows, other than what the row is about.
func details(rows []alertRow) {
	if len(rows) < 2 {
		return
	}
	values := map[string]map[string]bool{}
	for _, r := range rows {
		for _, kv := range alertLabels(r.Labels) {
			k, v, _ := strings.Cut(kv, "=")
			if values[k] == nil {
				values[k] = map[string]bool{}
			}
			values[k][v] = true
		}
	}
	for i := range rows {
		var parts []string
		for _, kv := range alertLabels(rows[i].Labels) {
			k, v, _ := strings.Cut(kv, "=")
			if len(values[k]) > 1 && k != "node" && k != "pod" && k != "namespace" {
				parts = append(parts, k+" "+v)
			}
		}
		rows[i].Detail = strings.Join(parts, ", ")
	}
}

// serverOf is the server an object is: a node, a controller or a host.
func serverOf(r findings.ObjectRef) string {
	switch r.Kind {
	case "Node", "Controller", "Host":
		return r.Name
	}
	return ""
}

// activeMutes are the hidings in force: not ended.
func activeMutes(ms []store.AlertMute, now time.Time) []store.AlertMute {
	var out []store.AlertMute
	for _, m := range ms {
		if m.Until == nil || now.Before(*m.Until) {
			out = append(out, m)
		}
	}
	return out
}

// muteFor finds the hiding of an alert: one for its server wins over one
// for every server.
func muteFor(ms []store.AlertMute, name, server string) int {
	found := -1
	for i, m := range ms {
		if m.Name != name {
			continue
		}
		if m.Server == "" && found < 0 {
			found = i
		}
		if m.Server != "" && m.Server == server {
			return i
		}
	}
	return found
}

// alertsOfFinding are the alerts about a problem and its symptoms.
func alertsOfFinding(f *findings.Finding, children []*findings.Finding) []findings.Alert {
	var out []findings.Alert
	seen := map[string]bool{}
	for _, x := range append([]*findings.Finding{f}, children...) {
		for _, a := range x.Alerts {
			if !seen[a.ID] {
				seen[a.ID] = true
				out = append(out, a)
			}
		}
	}
	return out
}

// sevClass is the icon class of an alert's severity.
func sevClass(sev string) string {
	switch snapshot.SeverityRank(sev) {
	case 0:
		return "crit"
	case 1:
		return "warn"
	}
	return "info"
}

// ---------------------------------------------------------------------------
// Hidings, cached: only this server changes them.

type muteCache struct {
	mu sync.Mutex
	by map[string][]store.AlertMute
}

// alertMutes are the cluster's hidings, ended ones included.
func (s *Server) alertMutes(cluster string) []store.AlertMute {
	if s.o.Store == nil {
		return nil
	}
	s.mutes.mu.Lock()
	defer s.mutes.mu.Unlock()
	if s.mutes.by == nil {
		s.mutes.by = map[string][]store.AlertMute{}
	}
	ms, ok := s.mutes.by[cluster]
	if !ok {
		var err error
		if ms, err = s.o.Store.AlertMutes(cluster); err != nil {
			s.log.Error("reading the hidden alerts", "err", err)
		}
		s.mutes.by[cluster] = ms
	}
	return ms
}

func (s *Server) forgetMutes(cluster string) {
	s.mutes.mu.Lock()
	delete(s.mutes.by, cluster)
	s.mutes.mu.Unlock()
}

// alertsFor lists a cluster's alerts with its hidings applied. A hiding
// "while it fires" ends once nothing it hides fires any more.
func (s *Server) alertsFor(st *engine.State) alertsData {
	d := alertsOf(st, s.alertMutes(st.Name), s.now())
	if !d.Read || st.Status == engine.StatusUnreachable {
		return d
	}
	for _, m := range d.Mutes {
		if m.WhileFiring && m.Hides == 0 && m.Name != "" {
			if err := s.o.Store.DeleteAlertMute(st.Name, m.Name, m.Server); err == nil {
				s.forgetMutes(st.Name)
			}
		}
	}
	return d
}

// shownAlerts are a problem's alerts that aren't hidden, for the pages.
func (s *Server) shownAlerts(cluster string, as []findings.Alert) []findings.Alert {
	if len(as) == 0 {
		return nil
	}
	active := activeMutes(s.alertMutes(cluster), s.now())
	if len(active) == 0 {
		return as
	}
	var out []findings.Alert
	for _, a := range as {
		if muteFor(active, a.Name, serverOf(a.About)) < 0 {
			out = append(out, a)
		}
	}
	return out
}

// hideFor turns a choice into when a hiding ends.
var hideFor = map[string]struct {
	d     time.Duration
	words string
}{
	"1d": {24 * time.Hour, "for a day"}, "1w": {7 * 24 * time.Hour, "for a week"},
	"firing": {0, "while it fires"}, "always": {0, "until shown again"},
}

var errNoSuchHiding = errors.New(`choose how long: "1d", "1w", "firing" or "always"`)

// hideAlerts hides alerts by name, maybe on one server, and records it.
func (s *Server) hideAlerts(r *http.Request, cluster, name, server, choice string) error {
	how, ok := hideFor[choice]
	if !ok {
		return errNoSuchHiding
	}
	if strings.TrimSpace(name) == "" {
		return errors.New("name the alert to hide")
	}
	m := store.AlertMute{Cluster: cluster, Name: name, Server: server, WhileFiring: choice == "firing", By: sessionUser(r)}
	if how.d > 0 {
		t := s.now().Add(how.d)
		m.Until = &t
	}
	if err := s.o.Store.SetAlertMute(m); err != nil {
		return err
	}
	s.forgetMutes(cluster)
	where := "everywhere"
	if server != "" {
		where = "on " + server
	}
	s.audit(r, "alert.hide", fmt.Sprintf("%s: %s %s, %s", cluster, name, where, how.words))
	return nil
}

func (s *Server) showAlerts(r *http.Request, cluster, name, server string) error {
	if err := s.o.Store.DeleteAlertMute(cluster, name, server); err != nil {
		return err
	}
	s.forgetMutes(cluster)
	where := "everywhere"
	if server != "" {
		where = "on " + server
	}
	s.audit(r, "alert.show", fmt.Sprintf("%s: %s %s", cluster, name, where))
	return nil
}

func (s *Server) alertsPage(w http.ResponseWriter, r *http.Request) {
	e := s.engineOf(w, r)
	if e == nil {
		return
	}
	st := e.State()
	nav := navOf(st)
	s.render(w, r, "alerts", &page{Title: "Alerts · " + e.Name(), Nav: "alerts", Cluster: &nav, Data: s.alertsFor(st)})
}

// alertsForm hides or shows alerts, from the Alerts page.
func (s *Server) alertsForm(w http.ResponseWriter, r *http.Request) {
	e := s.engineOf(w, r)
	if e == nil {
		return
	}
	name, server := r.PostFormValue("name"), r.PostFormValue("server")
	var err error
	if r.PostFormValue("action") == "show" {
		err = s.showAlerts(r, e.Name(), name, server)
	} else {
		err = s.hideAlerts(r, e.Name(), name, server, r.PostFormValue("for"))
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/c/"+e.Name()+"/alerts", http.StatusSeeOther)
}

type apiAlert struct {
	ID          string             `json:"id"`
	Name        string             `json:"name"`
	Severity    string             `json:"severity,omitempty"`
	Labels      map[string]string  `json:"labels"`
	Summary     string             `json:"summary,omitempty"`
	Description string             `json:"description,omitempty"`
	Runbook     string             `json:"runbookUrl,omitempty"`
	Since       *time.Time         `json:"since,omitempty"`
	About       findings.ObjectRef `json:"about"`
	Findings    []string           `json:"findings"`
	Hidden      bool               `json:"hidden,omitempty"`
}

// apiAlerts lists the firing alerts, with the IDs of the problems they are
// about and whether they are hidden. It answers 200 with read: false when
// they can't be read.
func (s *Server) apiAlerts(w http.ResponseWriter, r *http.Request) {
	e := s.engineOf(w, r)
	if e == nil {
		return
	}
	d := s.alertsFor(e.State())
	out := struct {
		Read   bool              `json:"read"`
		From   string            `json:"from,omitempty"`
		Alerts []apiAlert        `json:"alerts"`
		Hidden []store.AlertMute `json:"hidden"`
	}{Read: d.Read, From: d.From, Alerts: []apiAlert{}, Hidden: []store.AlertMute{}}
	for _, row := range d.Rows {
		a := apiAlert{ID: row.ID, Name: row.Name, Severity: row.Severity, Labels: row.Labels, Summary: row.Summary,
			Description: row.Description, Runbook: row.Runbook, About: row.About, Findings: []string{}, Hidden: row.Mute != nil}
		if !row.Since.IsZero() {
			t := row.Since
			a.Since = &t
		}
		for _, f := range row.Problems {
			a.Findings = append(a.Findings, f.ID)
		}
		out.Alerts = append(out.Alerts, a)
	}
	for _, m := range d.Mutes {
		out.Hidden = append(out.Hidden, m.AlertMute)
	}
	writeJSON(w, http.StatusOK, out)
}

// apiHideAlerts hides alerts: {"name", "server" (optional), "for": "1d",
// "1w", "firing" or "always"}.
func (s *Server) apiHideAlerts(w http.ResponseWriter, r *http.Request) {
	e := s.engineOf(w, r)
	if e == nil {
		return
	}
	var req struct{ Name, Server, For string }
	if err := decodeJSON(w, r, &req); err != nil {
		return
	}
	if err := s.hideAlerts(r, e.Name(), req.Name, req.Server, req.For); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.apiAlerts(w, r)
}

// apiShowAlerts shows hidden alerts again: {"name", "server"}.
func (s *Server) apiShowAlerts(w http.ResponseWriter, r *http.Request) {
	e := s.engineOf(w, r)
	if e == nil {
		return
	}
	var req struct{ Name, Server string }
	if err := decodeJSON(w, r, &req); err != nil {
		return
	}
	if err := s.showAlerts(r, e.Name(), req.Name, req.Server); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.apiAlerts(w, r)
}

// alertLabels are an alert's labels worth showing: not the ones that only
// say where Prometheus scraped it. A host exporter's pod, namespace and
// container are its own, not what the alert is about, so they go too.
func alertLabels(l map[string]string) []string {
	host := alerts.FromHostExporter(l)
	var out []string
	for _, k := range sortedKeys(l) {
		switch k {
		case "severity", "job", "endpoint", "prometheus", "service", "instance", "uid", "metrics_path":
			continue
		case "pod", "namespace", "container":
			if host {
				continue
			}
		}
		if strings.HasPrefix(k, "__") {
			continue
		}
		out = append(out, k+"="+l[k])
	}
	return out
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// decodeJSON reads a small JSON body, answering 400 when it can't.
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) error {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "the body isn't valid JSON: "+err.Error())
		return err
	}
	return nil
}
