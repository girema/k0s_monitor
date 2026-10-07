package web

import (
	"bytes"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"k0s_monitor/internal/cluster"
	"k0s_monitor/internal/engine"
	"k0s_monitor/internal/findings"
	"k0s_monitor/internal/glossary"
	"k0s_monitor/internal/priority"
	"k0s_monitor/internal/remedy"
	"k0s_monitor/internal/snapshot"
	"k0s_monitor/internal/version"
)

// page is what every template gets.
type page struct {
	// Status is the HTTP status; zero is 200.
	Status int
	Title  string
	Mode   string
	Basic  bool
	// Theme is "light" or "dark" when the browser chose one; empty follows
	// the computer's setting.
	Theme string
	// NavHidden is true when the browser hid the menu on the left.
	NavHidden bool
	CSRF      string
	User      string
	NoAuth    bool
	Nav       string
	Path      string
	Clusters  []navCluster
	// Cluster is the cluster the page is about, if any.
	Cluster     *navCluster
	Unread      int
	Host        string
	URL         string
	CertWarning string
	Version     string
	Data        any
}

type navCluster struct {
	Name     string
	Status   engine.Status
	Icon     string // good, warn, serious, crit, info
	Mark     string // ✓ ▲ ! ✕ …
	Summary  string // version, nodes and pods
	Plain    string // servers and apps: Basic mode's words, as in the overview's sentence
	Problems int
	Hot      bool // something to fix now (P1)
	Today    bool // something to fix today (P2), nothing now
	// AlertsRead says Prometheus's alerts can be read; Alerts is how many
	// fire.
	AlertsRead bool
	Alerts     int
}

var pageFiles = []string{"login", "clusters", "overview", "problems", "finding", "pod", "apps", "servers", "storage", "k0s", "settings", "addcluster", "clustersettings", "notfound", "glossary", "secrets", "secret", "report", "addnode", "alerts"}

func (s *Server) parseTemplates() error {
	s.pages = map[string]*template.Template{}
	base, err := template.New("").Funcs(funcs(s.now)).Funcs(template.FuncMap{"shownAlerts": s.shownAlerts}).ParseFS(assets, "templates/layout.html", "templates/parts.html")
	if err != nil {
		return err
	}
	for _, name := range pageFiles {
		t, err := base.Clone()
		if err != nil {
			return err
		}
		if _, err := t.ParseFS(assets, "templates/"+name+".html"); err != nil {
			return fmt.Errorf("template %s: %w", name, err)
		}
		s.pages[name] = t
	}
	_, err = fs.Stat(assets, "static/app.css")
	return err
}

// modeOf reads the Basic/Full choice: ?mode= wins, then the cookie, then
// the configured default.
func (s *Server) modeOf(w http.ResponseWriter, r *http.Request) string {
	m := r.URL.Query().Get("mode")
	if m == "basic" || m == "full" {
		http.SetCookie(w, &http.Cookie{Name: "mode", Value: m, Path: "/", MaxAge: 365 * 24 * 3600,
			Secure: true, SameSite: http.SameSiteStrictMode})
		return m
	}
	if c, err := r.Cookie("mode"); err == nil && (c.Value == "basic" || c.Value == "full") {
		return c.Value
	}
	if v, _ := s.o.Store.Setting("ui.defaultMode"); v == "basic" || v == "full" {
		return v
	}
	return s.o.Config.UI.DefaultMode
}

// themeOf reads the light or dark choice: ?theme= wins (for browsers
// without the page script), then the cookie the page script sets. Empty
// follows the computer's setting.
func themeOf(w http.ResponseWriter, r *http.Request) string {
	cookie := func(value string, maxAge int) {
		http.SetCookie(w, &http.Cookie{Name: "theme", Value: value, Path: "/", MaxAge: maxAge,
			Secure: true, SameSite: http.SameSiteStrictMode})
	}
	switch t := r.URL.Query().Get("theme"); t {
	case "light", "dark":
		cookie(t, 365*24*3600)
		return t
	case "system":
		cookie("", -1)
		return ""
	}
	if c, err := r.Cookie("theme"); err == nil && (c.Value == "light" || c.Value == "dark") {
		return c.Value
	}
	return ""
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, name string, p *page) {
	p.Mode = s.modeOf(w, r)
	p.Theme = themeOf(w, r)
	if c, err := r.Cookie("nav"); err == nil && c.Value == "hidden" {
		p.NavHidden = true
	}
	p.Basic = p.Mode == "basic"
	if c := p.Cluster; c != nil && c.AlertsRead && s.o.Fleet != nil {
		if e := s.o.Fleet.Get(c.Name); e != nil {
			c.Alerts = s.alertsFor(e.State()).Shown
		}
	}
	p.NoAuth = s.o.NoAuth
	p.Path = r.URL.Path
	p.Host = s.o.Host
	p.URL = s.o.URL
	p.Version = version.Version
	if sess := sessionOf(r); sess != nil {
		p.CSRF, p.User = sess.CSRF, sess.User
		p.Clusters = s.navClusters()
		if _, unread, err := s.o.Store.Notifications(sess.User, 0); err == nil {
			p.Unread = unread
		}
	}
	if !s.o.CertExpires.IsZero() {
		if left := s.o.CertExpires.Sub(s.now()); left < 30*24*time.Hour {
			p.CertWarning = fmt.Sprintf("The certificate of this page expires in %d days. On the jump host, run: sudo k0s-monitor init --renew-cert", int(left.Hours()/24))
		}
	}
	t := s.pages[name]
	if t == nil {
		http.Error(w, "unknown page "+name, http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	tmpl := "layout"
	if name == "login" {
		tmpl = "bare"
	}
	if err := t.ExecuteTemplate(&buf, tmpl, p); err != nil {
		s.log.Error("rendering page", "page", name, "err", err)
		http.Error(w, "The page could not be shown: "+err.Error(), http.StatusInternalServerError)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	if p.Status != 0 {
		w.WriteHeader(p.Status)
	}
	_, _ = w.Write(buf.Bytes())
}

func (s *Server) notFound(w http.ResponseWriter, r *http.Request, msg string) {
	s.render(w, r, "notfound", &page{Title: "Not found", Data: msg, Status: http.StatusNotFound})
}

func (s *Server) navClusters() []navCluster {
	var out []navCluster
	for _, e := range s.o.Fleet.Engines() {
		out = append(out, navOf(e.State()))
	}
	return out
}

func navOf(st *engine.State) navCluster {
	n := navCluster{Name: st.Name, Status: st.Status}
	roots := st.Counts[findings.P1] + st.Counts[findings.P2] + st.Counts[findings.P3] + st.Counts[findings.P4]
	// The badge counts what nobody has taken yet, as the problems page
	// lists them; the mark still shows how the cluster is.
	n.Problems = roots
	for _, f := range st.Findings {
		if f.Quiet() && !f.IsSymptom() && !f.IsHygiene() {
			n.Problems--
		}
	}
	n.Hot = st.Counts[findings.P1] > 0
	if s := st.Snapshot; s != nil && s.Metrics != nil && s.Metrics.AlertsRead {
		n.AlertsRead, n.Alerts = true, len(s.Metrics.Alerts)
	}
	n.Today = !n.Hot && st.Counts[findings.P2] > 0
	switch {
	case st.Status == engine.StatusConnecting:
		n.Icon, n.Mark, n.Summary = "info", "…", "connecting"
	case st.Status == engine.StatusUnreachable:
		n.Icon, n.Mark, n.Summary = "crit", "✕", "can't be reached"
	case st.Counts[findings.P1] > 0:
		n.Icon, n.Mark = "crit", "!"
	case st.Counts[findings.P2] > 0:
		n.Icon, n.Mark = "serious", "▲"
	case roots > 0:
		n.Icon, n.Mark = "warn", "▲"
	default:
		n.Icon, n.Mark = "good", "✓"
	}
	if n.Summary == "" && st.Info != nil {
		n.Summary = fmt.Sprintf("%s · %s · %s", st.Info.Version, plural(st.Info.Nodes, "node"), plural(st.Info.Pods, "pod"))
		n.Plain = plural(st.Info.Nodes, "server")
		if st.Snapshot != nil {
			n.Plain += " · " + plural(userApps(st.Snapshot), "app")
		}
	}
	if n.Plain == "" {
		n.Plain = n.Summary
	}
	return n
}

// ---------------------------------------------------------------------------
// Template functions

func funcs(now func() time.Time) template.FuncMap {
	since := func(v any) (time.Duration, bool) {
		t, ok := toTime(v)
		if !ok {
			return 0, false
		}
		return now().Sub(t), true
	}
	return template.FuncMap{
		"pri":        func(p findings.Priority) string { return strings.ToLower(string(p)) },
		"urg":        urgClass,
		"plainLabel": func(p findings.Priority) string { return p.PlainLabel() },
		"cat":        categoryLabel,
		"ago": func(v any) string {
			d, ok := since(v)
			if !ok {
				return "—"
			}
			return ago(d)
		},
		"agoPlain": func(v any) string {
			d, ok := since(v)
			if !ok {
				return "never"
			}
			return agoPlain(d)
		},
		"isNew": func(f *findings.Finding) bool {
			return f.FirstSeen != nil && now().Sub(*f.FirstSeen) < 15*time.Minute
		},
		"stamp": stamp,
		// gloss marks the technical terms of a text with their explanation;
		// newGloss marks them once across a page ({{$g.Mark text}}).
		"gloss":      glossary.Annotate,
		"newGloss":   glossary.NewMarker,
		"plural":     plural,
		"lower":      strings.ToLower,
		"lowerFirst": lowerFirst,
		// clause makes a sentence part of another: "No answer." → "no answer".
		"clause":      func(s string) string { return strings.TrimSuffix(lowerFirst(strings.TrimSpace(s)), ".") },
		"join":        strings.Join,
		"hasPrefix":   strings.HasPrefix,
		"healthCls":   healthClass,
		"healthIc":    healthIcon,
		"meterW":      func(v int) int { return max(0, min(v, 100)) },
		"lines":       func(s string) []string { return nonEmptyLines(s) },
		"ref":         func(r findings.ObjectRef) string { return r.String() },
		"plainRef":    plainRef,
		"plainChange": plainChange,
		"sevClass":    sevClass,
		"plainSeverity": func(s string) string {
			switch snapshot.SeverityRank(s) {
			case 0:
				return "urgent"
			case 2:
				return "for information"
			}
			return strings.ToLower(s)
		},
		"alertLabels": alertLabels,
		"sameObject":  sameObject,
		"plainSteps":  func(ss []findings.Step) []findings.Step { return filterSteps(ss, true) },
		"techSteps":   func(ss []findings.Step) []findings.Step { return filterSteps(ss, false) },
		"podLink":     podLink,
		"errorText":   errorText,
		"findingURL":  func(c, id string) string { return "/c/" + c + "/problems/" + id },
		"size":        sizeText,
		"add":         func(a, b int) int { return a + b },
		"sub":         func(a, b int) int { return a - b },
		"count":       func(m map[findings.Priority]int, p string) int { return m[findings.Priority(p)] },
		"list4":       func() []string { return []string{"P1", "P2", "P3", "P4"} },
		"dict": func(kv ...any) map[string]any {
			m := map[string]any{}
			for i := 0; i+1 < len(kv); i += 2 {
				m[fmt.Sprint(kv[i])] = kv[i+1]
			}
			return m
		},
		"ifs": func(cond bool, a, b string) string {
			if cond {
				return a
			}
			return b
		},
	}
}

// plainNouns are Basic mode's words for kinds of objects.
var plainNouns = map[string]string{
	"Pod": "app part", "Deployment": "app", "StatefulSet": "app", "DaemonSet": "app", "ReplicaSet": "app",
	"CronJob": "scheduled job", "Job": "job", "Node": "server", "PersistentVolumeClaim": "storage",
	"PersistentVolume": "disk", "Service": "service", "Ingress": "web address", "Namespace": "area",
	"StorageClass": "storage type", "Secret": "secret", "ConfigMap": "settings",
}

// plainRef names an object in Basic mode: "app part web-5d4c", "server
// worker-3".
func plainRef(r findings.ObjectRef) string {
	noun := plainNouns[r.Kind]
	if noun == "" {
		noun = strings.ToLower(r.Kind)
	}
	return noun + " " + r.Name
}

// plainChanges are Basic mode's words for what an update changed in an
// app (remedy.TemplateChanges); "env X" and the like are prefixes.
var plainChanges = map[string]string{
	"image":                     "version",
	"container":                 "part",
	"command":                   "start command",
	"args":                      "start options",
	"env":                       "setting",
	"env from":                  "settings taken from",
	"volume":                    "storage",
	"mount":                     "folder",
	"liveness probe":            "health check",
	"readiness probe":           "ready check",
	"startup probe":             "start-up check",
	"memory request":            "memory reserved",
	"CPU request":               "CPU reserved",
	"node selector":             "servers it may run on",
	"service account":           "account",
	"host network":              "uses the server's network",
	"fs group":                  "file group",
	"read-only root filesystem": "read-only files",
	"privileged":                "full access to its server",
}

// plainChange names a change in Basic mode: "setting DATABASE_URL" for
// "env DATABASE_URL".
func plainChange(what string) string {
	if w, ok := plainChanges[what]; ok {
		return w
	}
	if strings.HasPrefix(what, "restarted") {
		return "restarted, nothing else changed"
	}
	for _, p := range []string{"env ", "volume ", "mount "} {
		if name, ok := strings.CutPrefix(what, p); ok {
			return plainChanges[strings.TrimSpace(p)] + " " + name
		}
	}
	return what
}

// sameObject reports whether every symptom is about the root's own object:
// then they are details of it rather than other things affected.
func sameObject(root *findings.Finding, children []*findings.Finding) bool {
	if root == nil || len(children) == 0 {
		return false
	}
	for _, c := range children {
		if c.Resource != root.Resource {
			return false
		}
	}
	return true
}

// filterSteps keeps the steps written for Basic mode (with a plain text),
// or the others: commands for whoever manages the cluster.
func filterSteps(ss []findings.Step, plain bool) []findings.Step {
	var out []findings.Step
	for _, s := range ss {
		if (s.Plain != "") == plain {
			out = append(out, s)
		}
	}
	return out
}

func urgClass(p findings.Priority) string {
	switch p {
	case findings.P1:
		return "now"
	case findings.P2:
		return "today"
	case findings.P3:
		return "plan"
	}
	return "sugg"
}

var categoryNames = map[findings.Category][2]string{
	findings.Nodes:        {"Nodes & VMs", "Servers"},
	findings.Workloads:    {"Workloads", "Apps"},
	findings.Storage:      {"Storage", "Storage"},
	findings.Network:      {"Network", "Network and name lookup"},
	findings.ControlPlane: {"Control plane", "k0s system"},
	findings.Fleet:        {"Connection", "Connection"},
	findings.Hygiene:      {"Hygiene", "Good practices"},
}

func categoryLabel(c findings.Category, basic bool) string {
	n, ok := categoryNames[c]
	if !ok {
		return string(c)
	}
	if basic {
		return n[1]
	}
	return n[0]
}

func healthClass(score int) string {
	switch {
	case score >= 90:
		return "good"
	case score >= 70:
		return "warn"
	case score >= 50:
		return "serious"
	}
	return "crit"
}

func healthIcon(score int) string {
	switch {
	case score >= 90:
		return "✓"
	case score >= 50:
		return "▲"
	}
	return "✕"
}

func toTime(v any) (time.Time, bool) {
	switch t := v.(type) {
	case time.Time:
		return t, !t.IsZero()
	case *time.Time:
		if t == nil {
			return time.Time{}, false
		}
		return *t, !t.IsZero()
	}
	return time.Time{}, false
}

// ago formats a duration compactly: "12 s", "5 min", "3 h", "2 d".
func ago(d time.Duration) string {
	switch {
	case d < 0:
		return "just now"
	case d < time.Minute:
		return fmt.Sprintf("%d s", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%d min", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d h", int(d.Hours()))
	}
	return fmt.Sprintf("%d d", int(d.Hours()/24))
}

// agoPlain formats it in words: "12 seconds ago", "about 3 hours ago".
func agoPlain(d time.Duration) string {
	switch {
	case d < 10*time.Second:
		return "just now"
	case d < time.Minute:
		return fmt.Sprintf("%d seconds ago", int(d.Seconds()))
	case d < 2*time.Minute:
		return "a minute ago"
	case d < time.Hour:
		return fmt.Sprintf("%d minutes ago", int(d.Minutes()))
	case d < 2*time.Hour:
		return "about an hour ago"
	case d < 48*time.Hour:
		return fmt.Sprintf("about %d hours ago", int(d.Hours()))
	}
	return fmt.Sprintf("%d days ago", int(d.Hours()/24))
}

func stamp(v any) string {
	t, ok := toTime(v)
	if !ok {
		return "—"
	}
	return t.UTC().Format("2006-01-02 15:04:05 UTC")
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	switch {
	case strings.HasSuffix(word, "s"):
		return fmt.Sprintf("%d %ses", n, word)
	case strings.HasSuffix(word, "y") && !strings.HasSuffix(word, "ey"):
		return fmt.Sprintf("%d %sies", n, strings.TrimSuffix(word, "y"))
	}
	return fmt.Sprintf("%d %ss", n, word)
}

func nonEmptyLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}

func podLink(clusterName string, r findings.ObjectRef) string {
	if r.Kind != "Pod" {
		return ""
	}
	return "/c/" + clusterName + "/pods/" + r.Namespace + "/" + r.Name
}

// ---------------------------------------------------------------------------
// Findings as the pages show them

// item is a root cause with its folded symptoms.
type item struct {
	*findings.Finding
	Children []*findings.Finding
}

// itemsOf groups findings (in display order) into root causes with their
// symptoms. Acknowledged and snoozed ones are left out unless showQuiet.
// problemsIn leaves out the good-practice suggestions, which aren't
// problems.
func problemsIn(fs []*findings.Finding) []*findings.Finding {
	var out []*findings.Finding
	for _, f := range fs {
		if !f.IsHygiene() {
			out = append(out, f)
		}
	}
	return out
}

func itemsOf(fs []*findings.Finding, showQuiet bool) []item {
	var out []item
	idx := map[string]int{}
	for _, f := range fs {
		if f.IsSymptom() {
			continue
		}
		if f.Quiet() && !showQuiet {
			continue
		}
		idx[f.ID] = len(out)
		out = append(out, item{Finding: f})
	}
	for _, f := range fs {
		if !f.IsSymptom() {
			continue
		}
		if i, ok := idx[f.ParentID]; ok {
			out[i].Children = append(out[i].Children, f)
		}
	}
	return out
}

func quietCount(fs []*findings.Finding) int {
	n := 0
	for _, f := range fs {
		if !f.IsSymptom() && f.Quiet() {
			n++
		}
	}
	return n
}

// group is one urgency level of the Basic problems page.
type group struct {
	Priority findings.Priority
	Label    string
	Intro    string
	Folded   bool
	Items    []item
}

func groupsOf(items []item) []group {
	gs := []group{
		{Priority: findings.P1, Label: "Fix now", Intro: "problems that affect your apps right now"},
		{Priority: findings.P2, Label: "Fix today", Intro: "problems that are not urgent yet, but will get worse"},
		{Priority: findings.P3, Label: "Plan ahead", Intro: "things to handle in the coming days", Folded: true},
		{Priority: findings.P4, Label: "Suggestions", Intro: "good practices; nothing is broken", Folded: true},
	}
	for _, it := range items {
		for i := range gs {
			if gs[i].Priority == it.Priority {
				gs[i].Items = append(gs[i].Items, it)
			}
		}
	}
	var out []group
	for _, g := range gs {
		if len(g.Items) > 0 {
			out = append(out, g)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// All clusters

type clusterCard struct {
	State *engine.State
	// PCounts are the Issues page's numbers per priority.
	PCounts  map[findings.Priority]int
	Nav      navCluster
	Top      *findings.Finding
	FromUI   bool
	Health   *priority.Health
	Stale    bool
	Problems int
}

type clustersData struct {
	Cards       []clusterCard
	P1, P2      int
	Unreachable int
	CanAdd      bool
	Full        bool
	MemoryMiB   int
}

func topRoot(st *engine.State) *findings.Finding {
	for _, f := range st.Findings {
		if !f.IsSymptom() && !f.Quiet() && !f.IsHygiene() {
			return f
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Overview

type check struct {
	Icon, Mark string
	Name       string
	Text       string
	Link       string
}

type nodeView struct {
	Name     string
	Ready    bool
	Status   string
	Icon     string
	Roles    string
	Version  string
	Pods     int
	Problems []string
	Link     string
}

type overviewData struct {
	State *engine.State
	// PCounts are the Issues page's numbers per priority, suggestions
	// included, so the tiles match it.
	PCounts    map[findings.Priority]int
	Items      []item
	Top        []item
	Checks     []check
	Nodes      []nodeView
	Sources    []check
	ReadyNodes int
	Apps       int
	AppsBad    int
	Headline   string
	Sentence   string
	HeroIcon   string
	Quiet      int
}

// nodeAddonRules report system add-ons that fail on specific nodes.
var nodeAddonRules = map[string]bool{"cni.unhealthy": true, "konnectivity.agent-down": true, "kube-proxy.unhealthy": true}

func overviewOf(clusterName string, st *engine.State) overviewData {
	return overviewWith(clusterName, st, alertsOf(st, nil, time.Time{}))
}

// overviewWith builds the overview with the cluster's alerts as shown,
// hidden ones left out.
func overviewWith(clusterName string, st *engine.State, al alertsData) overviewData {
	d := overviewData{State: st, PCounts: problemsOf(st, "", "", false, false).PCounts}
	d.Items = itemsOf(problemsIn(st.Findings), false)
	d.Quiet = quietCount(problemsIn(st.Findings))
	d.Top = d.Items
	if len(d.Top) > 6 {
		d.Top = d.Top[:6]
	}
	areaOf := func(f *findings.Finding) findings.Category {
		if f.Category == findings.Workloads && f.Resource.Namespace == "kube-system" {
			return findings.ControlPlane // k0s's own components, not the user's apps
		}
		return f.Category
	}
	byCat := map[findings.Category][]item{}
	// affected are the areas that only have symptoms of a problem
	// elsewhere, with the most urgent one: an app down because its server
	// stopped isn't running normally either.
	affected := map[findings.Category]findings.Priority{}
	for _, it := range d.Items {
		byCat[areaOf(it.Finding)] = append(byCat[areaOf(it.Finding)], it)
		for _, ch := range it.Children {
			if p, ok := affected[areaOf(ch)]; !ok || ch.Priority.Rank() < p.Rank() {
				affected[areaOf(ch)] = ch.Priority
			}
		}
	}
	badWorkloads := map[string]bool{}
	for _, f := range st.Findings {
		switch f.Resource.Kind {
		case "Deployment", "StatefulSet", "DaemonSet", "CronJob":
			if f.Resource.Namespace != "kube-system" {
				badWorkloads[f.Resource.String()] = true
			}
		}
	}
	d.AppsBad = len(badWorkloads)
	if snap := st.Snapshot; snap != nil {
		d.Apps = userApps(snap)
		nodeProblems := map[string][]string{}
		for _, f := range st.Findings {
			switch {
			case f.Resource.Kind == "Node":
				nodeProblems[f.Resource.Name] = append(nodeProblems[f.Resource.Name], f.Title)
			case nodeAddonRules[f.RuleID]:
				// A system add-on that fails on some nodes is a problem of each.
				for _, n := range f.Links.Nodes {
					nodeProblems[n] = append(nodeProblems[n], f.Title)
				}
			}
		}
		for _, n := range snap.Nodes {
			nv := nodeView{Name: n.Name, Version: n.Status.NodeInfo.KubeletVersion, Pods: len(snap.PodsOnNode(n.Name)),
				Problems: nodeProblems[n.Name]}
			nv.Ready = snapshot.IsNodeReady(n)
			var roles []string
			for k := range n.Labels {
				if r, ok := strings.CutPrefix(k, "node-role.kubernetes.io/"); ok && r != "" {
					roles = append(roles, r)
				}
			}
			sort.Strings(roles)
			nv.Roles = strings.Join(roles, ", ")
			switch {
			case !nv.Ready:
				nv.Status, nv.Icon = "NotReady", "crit"
			case len(nv.Problems) > 0:
				nv.Status, nv.Icon = "Problem", "serious"
			case n.Spec.Unschedulable:
				nv.Status, nv.Icon = "Cordoned", "warn"
			default:
				nv.Status, nv.Icon = "Ready", "good"
			}
			d.Nodes = append(d.Nodes, nv)
		}
		d.ReadyNodes = countReady(d.Nodes)
	}

	// "What we checked", in plain words.
	nodes := len(d.Nodes)
	add := func(c findings.Category, okText, badText string, link string) {
		its := byCat[c]
		ch := check{Name: categoryLabel(c, true), Link: link}
		p, symptoms := affected[c]
		switch {
		case len(its) == 0 && symptoms:
			ch.Text = "affected by a problem elsewhere"
			if c == findings.Workloads {
				ch.Text = badText + ", because of a problem elsewhere"
			}
			ch.Icon, ch.Mark = "warn", "▲"
			if p == findings.P1 || p == findings.P2 {
				ch.Icon, ch.Mark = "crit", "✕"
			}
		case len(its) == 0:
			ch.Icon, ch.Mark, ch.Text = "good", "✓", okText
		case its[0].Priority == findings.P1 || its[0].Priority == findings.P2:
			ch.Icon, ch.Mark, ch.Text = "crit", "✕", badText
		default:
			ch.Icon, ch.Mark, ch.Text = "warn", "▲", badText
		}
		d.Checks = append(d.Checks, ch)
	}
	notReady := nodes - countReady(d.Nodes)
	serversOK := fmt.Sprintf("all %d servers respond normally", nodes)
	if nodes == 1 {
		serversOK = "the server responds normally"
	}
	serversBad := plural(len(byCat[findings.Nodes]), "problem")
	if notReady > 0 {
		serversBad = fmt.Sprintf("%d of %d not responding", notReady, nodes)
		if others := len(byCat[findings.Nodes]) - notReady; others > 0 {
			serversBad += ", and " + plural(others, "other problem")
		}
	}
	base := "/c/" + url.PathEscape(clusterName)
	add(findings.Nodes, serversOK, serversBad, base+"/servers")
	appsOK := fmt.Sprintf("all %d apps run normally", d.Apps)
	switch d.Apps {
	case 0:
		appsOK = "no apps installed yet"
	case 1:
		appsOK = "the app runs normally"
	}
	appsBad := fmt.Sprintf("%d of %d apps have a problem", d.AppsBad, d.Apps)
	if d.AppsBad == 1 {
		appsBad = fmt.Sprintf("1 of %s has a problem", plural(d.Apps, "app"))
	}
	add(findings.Workloads, appsOK, appsBad, base+"/apps")
	add(findings.Storage, "working", plural(len(byCat[findings.Storage]), "problem"), base+"/storage")
	add(findings.Network, "working", plural(len(byCat[findings.Network]), "problem"), base+"/apps?tab=services")
	add(findings.ControlPlane, "working", plural(len(byCat[findings.ControlPlane]), "problem"), base+"/k0s")
	if al.Read {
		// Alerts from the cluster's own monitoring, when it shares them.
		ch := check{Name: "Monitoring alerts", Link: base + "/alerts", Icon: "good", Mark: "✓", Text: "none"}
		if n := al.Shown; n > 0 {
			ch.Icon, ch.Mark = "warn", "▲"
			if sevClass(al.Groups[0].Severity) == "crit" {
				ch.Icon, ch.Mark = "crit", "✕"
			}
			ch.Text = plural(n, "alert")
			switch {
			case al.Linked == n:
				ch.Text += ", all about the problems here"
			case al.Linked > 0:
				ch.Text += fmt.Sprintf(", %d about the problems here", al.Linked)
			}
		}
		if al.Hidden > 0 {
			ch.Text += fmt.Sprintf(" (%d hidden)", al.Hidden)
		}
		d.Checks = append(d.Checks, ch)
	}

	// The status line.
	now := st.Counts[findings.P1]
	today := st.Counts[findings.P2]
	switch {
	case st.Status == engine.StatusUnreachable:
		d.HeroIcon = "crit"
		d.Headline = clusterName + " can't be reached"
		if st.Error != nil {
			d.Sentence = st.Error.Plain + " " + st.Error.Hint
		}
	case st.Health == nil:
		d.HeroIcon = "info"
		d.Headline = "Checking " + clusterName + "…"
		d.Sentence = "The first check runs right after connecting. This page updates by itself."
	case now > 0:
		d.HeroIcon = "crit"
		d.Headline = clusterName + " needs your attention"
		d.Sentence = fmt.Sprintf("%s to fix now.", plural(now, "problem"))
	case today > 0:
		d.HeroIcon = "serious"
		d.Headline = clusterName + " needs your attention today"
		d.Sentence = fmt.Sprintf("%s to fix today. Nothing is urgent right now.", plural(today, "problem"))
	case len(d.Items) > 0:
		d.HeroIcon = "warn"
		d.Headline = clusterName + " is working"
		d.Sentence = "There are a few things to plan for, but nothing needs fixing now."
	default:
		d.HeroIcon = "good"
		d.Headline = clusterName + " is working normally"
		d.Sentence = "Everything we checked is working."
	}
	if st.Health != nil && st.Status != engine.StatusUnreachable && nodes > 0 {
		normal := 0
		for _, n := range d.Nodes {
			if n.Status == "Ready" {
				normal++
			}
		}
		if d.Apps > 0 {
			d.Sentence += fmt.Sprintf(" %d of %s and %d of %s run normally.", normal, plural(nodes, "server"),
				max(d.Apps-d.AppsBad, 0), plural(d.Apps, "app"))
		} else {
			d.Sentence += fmt.Sprintf(" %d of %s %s normally.", normal, plural(nodes, "server"), ifStr(nodes == 1, "runs", "run"))
		}
	}

	// Data sources (Full mode).
	src := func(ok bool, name, detail string) {
		c := check{Name: name, Text: detail, Icon: "good", Mark: "✓"}
		if !ok {
			c.Icon, c.Mark = "warn", "▲"
		}
		d.Sources = append(d.Sources, c)
	}
	src(st.Status != engine.StatusUnreachable, "API server watch (informers)", ifStr(st.Status == engine.StatusUnreachable, "no connection", "live"))
	if st.Info != nil {
		src(st.Info.MetricsAPI, "Metrics API (metrics-server)", ifStr(st.Info.MetricsAPI, "available", "not found"))
		src(len(st.Info.Unreadable) == 0, "Permissions", ifStr(len(st.Info.Unreadable) == 0, "every kind readable", fmt.Sprintf("%d kinds can't be read", len(st.Info.Unreadable))))
		src(st.Info.K0s, "k0s", ifStr(st.Info.K0s, "detected", "not detected: generic Kubernetes checks only"))
	}
	if st.Info != nil && st.Info.Prometheus != nil {
		p := st.Info.Prometheus
		text := p.Message
		if p.State == "ok" {
			text = p.Target + ": " + p.Message
		}
		src(p.State == "ok", "Metrics (Prometheus or VictoriaMetrics)", text)
		if p.State == "ok" {
			if al.Read {
				text := fmt.Sprintf("%s through the %s, %d linked to issues", plural(len(al.Rows), "firing alert"), al.From, al.Linked)
				if al.Hidden > 0 {
					text += fmt.Sprintf(", %d hidden", al.Hidden)
				}
				src(true, "Alerts", text)
			} else {
				src(false, "Alerts", "neither the alerts API nor the ALERTS series answered")
			}
		}
		if len(p.Fallbacks) > 0 {
			src(true, "Fallbacks", strings.Join(p.Fallbacks, "; "))
		}
	} else {
		src(false, "Metrics (Prometheus or VictoriaMetrics)", "not checked yet")
	}
	return d
}

// userApps counts the long-running workloads outside kube-system: what
// Basic mode calls apps.
func userApps(snap *snapshot.Snapshot) int {
	n := 0
	for _, o := range snap.Deployments {
		if o.Namespace != "kube-system" {
			n++
		}
	}
	for _, o := range snap.StatefulSets {
		if o.Namespace != "kube-system" {
			n++
		}
	}
	for _, o := range snap.DaemonSets {
		if o.Namespace != "kube-system" {
			n++
		}
	}
	for _, o := range snap.CronJobs {
		if o.Namespace != "kube-system" {
			n++
		}
	}
	return n
}

func countReady(ns []nodeView) int {
	n := 0
	for _, x := range ns {
		if x.Ready {
			n++
		}
	}
	return n
}

func ifStr(c bool, a, b string) string {
	if c {
		return a
	}
	return b
}

// ---------------------------------------------------------------------------
// Problems

type problemsData struct {
	State     *engine.State
	Items     []item
	Groups    []group
	ShowQuiet bool
	Quiet     int
	Priority  string
	Category  string
	PCounts   map[findings.Priority]int
	CatCounts []catCount
	// Total counts the problems; Suggestions the good practices, which
	// Full mode lists too.
	Total       int
	Suggestions int
}

type catCount struct {
	Category findings.Category
	Roots    int
	Folded   int
}

// problemsOf lists the problems for the Problems page. Basic mode leaves
// out the good-practice suggestions; Full mode lists them last.
func problemsOf(st *engine.State, prio, cat string, showQuiet, basic bool) problemsData {
	fs := st.Findings
	if basic {
		fs = problemsIn(fs)
	}
	all := itemsOf(fs, showQuiet)
	d := problemsData{State: st, ShowQuiet: showQuiet, Quiet: quietCount(fs), Priority: prio, Category: cat,
		PCounts: map[findings.Priority]int{}, Suggestions: st.Suggestions}
	counts := map[findings.Category]*catCount{}
	var order []findings.Category
	for _, c := range []findings.Category{findings.Nodes, findings.Workloads, findings.Storage, findings.Network, findings.ControlPlane, findings.Fleet, findings.Hygiene} {
		counts[c] = &catCount{Category: c}
		order = append(order, c)
	}
	for _, it := range all {
		d.PCounts[it.Priority]++
		if c := counts[it.Category]; c != nil {
			c.Roots++
		}
		for _, ch := range it.Children {
			if c := counts[ch.Category]; c != nil {
				c.Folded++
			}
		}
	}
	for _, c := range order {
		if counts[c].Roots > 0 || counts[c].Folded > 0 {
			d.CatCounts = append(d.CatCounts, *counts[c])
		}
	}
	for _, it := range all {
		if prio != "" && string(it.Priority) != prio {
			continue
		}
		if cat != "" && string(it.Category) != cat {
			continue
		}
		d.Items = append(d.Items, it)
	}
	for _, it := range all {
		if !it.IsHygiene() {
			d.Total++
		}
	}
	d.Groups = groupsOf(d.Items)
	return d
}

// ---------------------------------------------------------------------------
// Finding detail

type findingData struct {
	State    *engine.State
	F        *findings.Finding
	Parent   *findings.Finding
	Children []*findings.Finding
	History  []occurrence
	Pods     []findings.ObjectRef
	Others   []findings.ObjectRef
	Resolved bool
	// Important are log lines that explain the problem, from LogPod.
	Important []string
	LogPod    findings.ObjectRef
	LogSource string
	// LogError says why the log could not be read, for example when the
	// node's konnectivity agent is down.
	LogError string
	// Matches are the known errors in that log.
	Matches []remedy.Match
	// SecretLink opens the Secret the finding is about.
	SecretLink string
	// Support is who helps with the cluster's product, from a pack.
	Support string
	// Alerts are Prometheus's alerts about the problem and its symptoms.
	Alerts []findings.Alert
	// AI is Explain with AI, when it is on.
	AI *aiView
}

type occurrence struct {
	First, Last string
	Resolved    string
	Priority    findings.Priority
	// Started is when it started, in words ("20 minutes ago").
	Started string
}

// errorText explains a connection error in one line.
func errorText(ce *cluster.ConnError) string {
	if ce == nil {
		return ""
	}
	return strings.TrimSpace(ce.Plain + " " + ce.Hint)
}
