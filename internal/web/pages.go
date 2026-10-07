package web

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k0s_monitor/internal/account"
	"k0s_monitor/internal/ai"
	"k0s_monitor/internal/engine"
	"k0s_monitor/internal/findings"
	"k0s_monitor/internal/podview"
	"k0s_monitor/internal/remedy"
	"k0s_monitor/internal/snapshot"
	"k0s_monitor/internal/store"
)

func (s *Server) clustersPage(w http.ResponseWriter, r *http.Request) {
	d := clustersData{CanAdd: s.o.CanStoreClusters && len(s.o.Fleet.Engines()) < 5}
	for _, e := range s.o.Fleet.Engines() {
		st := e.State()
		c := clusterCard{State: st, Nav: navOf(st), Top: topRoot(st), FromUI: e.Cluster().FromUI, Health: st.Health,
			Stale: st.Status == engine.StatusUnreachable, PCounts: problemsOf(st, "", "", false, false).PCounts}
		c.Problems = c.Nav.Problems
		d.P1 += st.Counts[findings.P1]
		d.P2 += st.Counts[findings.P2]
		if st.Status == engine.StatusUnreachable {
			d.Unreachable++
		}
		d.Cards = append(d.Cards, c)
	}
	d.Full = len(d.Cards) >= 5
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	d.MemoryMiB = int(ms.Sys >> 20)
	s.render(w, r, "clusters", &page{Title: "All clusters", Nav: "clusters", Data: d})
}

func (s *Server) overviewPage(w http.ResponseWriter, r *http.Request) {
	e := s.engineOf(w, r)
	if e == nil {
		return
	}
	st := e.State()
	nav := navOf(st)
	s.render(w, r, "overview", &page{Title: e.Name(), Nav: "overview", Cluster: &nav, Data: overviewWith(e.Name(), st, s.alertsFor(st))})
}

func (s *Server) problemsPage(w http.ResponseWriter, r *http.Request) {
	e := s.engineOf(w, r)
	if e == nil {
		return
	}
	st := e.State()
	nav := navOf(st)
	q := r.URL.Query()
	d := problemsOf(st, q.Get("priority"), q.Get("category"), q.Get("show") == "all", s.modeOf(w, r) == "basic")
	s.render(w, r, "problems", &page{Title: "Problems · " + e.Name(), Nav: "problems", Cluster: &nav, Data: d})
}

// appsPage lists every workload with its pods (tab "services": every
// Service), filtered by the search box, a namespace and "only problems".
func (s *Server) appsPage(w http.ResponseWriter, r *http.Request) {
	e := s.engineOf(w, r)
	if e == nil {
		return
	}
	st := e.State()
	nav := navOf(st)
	v := r.URL.Query()
	full := s.modeOf(w, r) == "full"
	q := appsQuery{Query: strings.TrimSpace(v.Get("q")), Namespace: v.Get("ns"), OnlyBad: v.Get("problems") == "1",
		SystemAsked: v.Get("system") == "1"}
	q.System = full || q.SystemAsked
	if v.Get("tab") == "services" {
		q.Tab = "services"
	}
	title := ifStr(full, "Workloads", "Apps")
	if q.Tab == "services" {
		title = "Services"
	}
	d := appsOf(st, q, s.now())
	if set := s.o.Packs.Current(); set != nil && st.Snapshot != nil {
		for i := range d.Apps {
			a := &d.Apps[i]
			var labels map[string]string
			if m := st.Snapshot.WorkloadMeta(snapshot.Workload{Kind: a.Kind, Namespace: a.Namespace, Name: a.Name}); m != nil {
				labels = m.Labels
			}
			if app := set.AppName(e.Name(), a.Kind, a.Namespace, a.Name, labels); app != nil {
				a.Friendly, a.About, a.Docs = app.Name, app.Description, app.Docs
				a.Search += " " + strings.ToLower(app.Name)
			}
		}
	}
	if full && secretsReadable(e) {
		d.SecretsLink = "/c/" + url.PathEscape(e.Name()) + "/secrets?ns=" + url.QueryEscape(q.Namespace)
	}
	s.render(w, r, "apps", &page{Title: title + " · " + e.Name(), Nav: "apps", Cluster: &nav, Data: d})
}

func (s *Server) serversPage(w http.ResponseWriter, r *http.Request) {
	e := s.engineOf(w, r)
	if e == nil {
		return
	}
	st := e.State()
	nav := navOf(st)
	d := serversOf(st, s.o.Config.Thresholds, r.URL.Query().Get("node"), s.now())
	s.render(w, r, "servers", &page{Title: "Servers · " + e.Name(), Nav: "servers", Cluster: &nav, Data: d})
}

func (s *Server) storagePage(w http.ResponseWriter, r *http.Request) {
	e := s.engineOf(w, r)
	if e == nil {
		return
	}
	st := e.State()
	nav := navOf(st)
	q := r.URL.Query()
	d := storageOf(st, s.o.Config.Thresholds, q.Get("ns"), q.Get("pvc"), q.Get("problems") == "1", s.now())
	s.render(w, r, "storage", &page{Title: "Storage · " + e.Name(), Nav: "storage", Cluster: &nav, Data: d})
}

func (s *Server) k0sPage(w http.ResponseWriter, r *http.Request) {
	e := s.engineOf(w, r)
	if e == nil {
		return
	}
	st := e.State()
	nav := navOf(st)
	d := k0sOf(st, s.o.Config.Thresholds, s.now())
	if e.Cluster().FromUI {
		d.Config = configOf(st, uploadedConfig(s.o.Store, e.Name()))
	}
	s.render(w, r, "k0s", &page{Title: "k0s system · " + e.Name(), Nav: "k0s", Cluster: &nav, Data: d})
}

func (s *Server) findingPage(w http.ResponseWriter, r *http.Request) {
	e := s.engineOf(w, r)
	if e == nil {
		return
	}
	st := e.State()
	id := r.PathValue("id")
	f := st.Finding(id)
	d := findingData{State: st, F: f}
	if f != nil && f.Resource.Kind == "Secret" && secretsReadable(e) {
		d.SecretLink = secretLink(e.Name(), f.Resource.Namespace, f.Resource.Name)
	}
	if sup, _ := s.o.Packs.Current().Support(e.Name()); sup != nil {
		d.Support = sup.Contact()
	}
	if f == nil {
		// Resolved since the link was made: show what the history knows.
		occ, _ := s.o.Store.History(e.Name(), id)
		if len(occ) == 0 {
			s.notFound(w, r, "This problem is not known. It may have been resolved more than 30 days ago.")
			return
		}
		d.Resolved = true
		d.F = &findings.Finding{ID: id, Cluster: e.Name(), Title: occ[0].Title, Priority: occ[0].Priority, State: findings.StateResolved}
		d.F.Plain.Title = occ[0].Title
	} else {
		if f.IsSymptom() {
			d.Parent = st.Finding(f.ParentID)
		}
		for _, c := range st.Findings {
			if c.ParentID == f.ID {
				d.Children = append(d.Children, c)
			}
		}
		d.Alerts = s.shownAlerts(e.Name(), alertsOfFinding(f, d.Children))
		d.AI = s.aiViewOf(st, f, s.modeOf(w, r) == "basic")
		for _, a := range f.Affected {
			if a.Kind == "Pod" {
				d.Pods = append(d.Pods, a)
			} else {
				d.Others = append(d.Others, a)
			}
		}
	}
	if f != nil && logRules[f.RuleID] && len(d.Pods) > 0 {
		s.importantLines(r.Context(), e, &d)
		if len(d.Matches) == 0 {
			crashLogFallback(st, &d, s.now())
		}
		d.Matches = otherMatches(f, d.Matches)
	}
	if occ, err := s.o.Store.History(e.Name(), id); err == nil {
		for _, o := range occ {
			oc := occurrence{First: stamp(o.FirstSeen), Last: stamp(o.LastSeen), Priority: o.Priority, Started: agoPlain(s.now().Sub(o.FirstSeen))}
			if o.ResolvedAt != nil {
				oc.Resolved = stamp(*o.ResolvedAt)
			}
			d.History = append(d.History, oc)
		}
	}
	nav := navOf(st)
	title := d.F.Title
	s.render(w, r, "finding", &page{Title: title, Nav: "problems", Cluster: &nav, Data: d})
}

// findingStateForm handles the acknowledge, snooze and reopen buttons.
func (s *Server) findingStateForm(w http.ResponseWriter, r *http.Request) {
	e := s.engineOf(w, r)
	if e == nil {
		return
	}
	id := r.PathValue("id")
	action := r.PostFormValue("action")
	var until *time.Time
	if action == "snooze" {
		d, ok := snoozeDurations[r.PostFormValue("for")]
		if !ok {
			http.Error(w, "unknown snooze duration", http.StatusBadRequest)
			return
		}
		t := s.now().Add(d)
		until = &t
	}
	if err := s.setFindingState(r, e, id, action, until); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	back := r.PostFormValue("back")
	http.Redirect(w, r, safeNext(back), http.StatusSeeOther)
}

var snoozeDurations = map[string]time.Duration{
	"1h": time.Hour, "4h": 4 * time.Hour, "1d": 24 * time.Hour, "1w": 7 * 24 * time.Hour,
}

type settingsData struct {
	Audit       []store.AuditEntry
	Message     string
	Error       string
	DefaultMode string
	Notify      []string
	Users       []userRow
	// AllowFrom lists who may open k0s-monitor; Open is true when
	// everyone who can reach it may.
	AllowFrom []string
	Open      bool
	// SecretValues is true while Secret values may be shown.
	SecretValues bool
	Packs        packsData
	// AI is the Explain with AI form, and Presets its providers.
	AI      *aiForm
	Presets []ai.Preset
}

func (s *Server) settingsPage(w http.ResponseWriter, r *http.Request) {
	s.renderSettings(w, r, "", "")
}

func (s *Server) renderSettings(w http.ResponseWriter, r *http.Request, msg, errMsg string) {
	s.renderSettingsWith(w, r, msg, errMsg, nil)
}

// renderSettingsWith renders the settings, with the AI form as submitted
// when form isn't nil.
func (s *Server) renderSettingsWith(w http.ResponseWriter, r *http.Request, msg, errMsg string, form *aiForm) {
	if form == nil {
		form = s.savedAIForm()
	}
	d := settingsData{Message: msg, Error: errMsg, DefaultMode: s.o.Config.UI.DefaultMode, Notify: s.o.Config.UI.Notify,
		AllowFrom: s.o.Config.AllowFrom, Open: len(s.o.Config.AllowFrom) == 0 && !s.o.NoAuth, SecretValues: s.secretValuesOn(),
		AI: form, Presets: ai.Presets}
	if v, _ := s.o.Store.Setting("ui.defaultMode"); v != "" {
		d.DefaultMode = v
	}
	d.Audit, _ = s.o.Store.AuditLog(50)
	d.Packs = s.packsData()
	if sess := sessionOf(r); sess != nil && !s.o.NoAuth {
		d.Users = s.userRows(sess.User)
	}
	if errMsg != "" || form.Error != "" {
		w.WriteHeader(http.StatusBadRequest)
	}
	s.render(w, r, "settings", &page{Title: "Settings", Nav: "settings", Data: d})
}

type clusterSettingsData struct {
	State   *engine.State
	FromUI  bool
	Server  string
	Context string
	// RemoveCommands delete k0s-monitor's read-only account from the
	// cluster, when k0s-monitor created one.
	RemoveCommands string
	Metrics        metricsForm
	K0s            k0sVersionForm
	Account        accountForm
	TLS            tlsForm
}

// settingsForms are the forms of a cluster's settings page as submitted;
// nil ones show the current settings.
type settingsForms struct {
	metrics *metricsForm
	k0s     *k0sVersionForm
	account *accountForm
	tls     *tlsForm
}

func (s *Server) clusterSettingsPage(w http.ResponseWriter, r *http.Request) {
	e := s.engineOf(w, r)
	if e == nil {
		return
	}
	var forms settingsForms
	switch r.URL.Query().Get("saved") {
	case "metrics":
		mf := metricsFormOf(e.Cluster(), e.State().Info)
		mf.Notice, mf.NoticeOK = "Saved. The cluster was restarted with the new metrics source; its state below updates within a minute.", true
		forms.metrics = &mf
	case "k0s":
		k := k0sVersionFormOf(e.Cluster(), e.State())
		k.Notice, k.NoticeOK = "Saved. The version check uses it from the next check on.", true
		forms.k0s = &k
	case "account":
		forms.account = &accountForm{Notice: "Done: k0s-monitor now uses its own read-only account, and the uploaded credentials were deleted from this machine.", OK: true}
	case "tls":
		forms.tls = &tlsForm{Notice: "Saved. The cluster was restarted; the state below updates within a minute.", NoticeOK: true}
	}
	s.renderClusterSettings(w, r, e, forms, http.StatusOK)
}

// renderClusterSettings shows a cluster's settings, with the forms as
// submitted when set.
func (s *Server) renderClusterSettings(w http.ResponseWriter, r *http.Request, e *engine.Engine, forms settingsForms, status int) {
	st := e.State()
	nav := navOf(st)
	c := e.Cluster()
	d := clusterSettingsData{State: st, FromUI: c.FromUI, Server: c.Server, Context: c.Context, Metrics: metricsFormOf(c, st.Info), K0s: k0sVersionFormOf(c, st)}
	if forms.metrics != nil {
		d.Metrics = *forms.metrics
	}
	if forms.k0s != nil {
		d.K0s = *forms.k0s
	}
	if forms.account != nil {
		d.Account = *forms.account
	}
	accountKind := ""
	if c.FromUI {
		if stored, err := s.o.Store.Clusters(); err == nil {
			for _, sc := range stored {
				if sc.Cluster.Name != c.Name {
					continue
				}
				accountKind = sc.Account
				switch sc.Account {
				case "readonly":
					d.RemoveCommands = account.RemoveCommands
				case "uploaded":
					d.Account.Uploaded = true
				}
			}
		}
	}
	d.TLS = tlsFormOf(c, st, accountKind)
	if forms.tls != nil {
		d.TLS.Notice, d.TLS.NoticeOK = forms.tls.Notice, forms.tls.NoticeOK
	}
	s.render(w, r, "clustersettings", &page{Title: "Settings · " + e.Name(), Nav: "clustersettings", Cluster: &nav, Data: d, Status: status})
}

// otherMatches leaves out the known errors the finding explains already.
func otherMatches(f *findings.Finding, ms []remedy.Match) []remedy.Match {
	var out []remedy.Match
	for _, m := range ms {
		if !strings.Contains(f.Remedy.LikelyCause, m.Cause()) {
			out = append(out, m)
		}
	}
	return out
}

// crashLogFallback shows what k0s-monitor read from the last crash of an
// affected pod when the log can't be read now, or says nothing known.
func crashLogFallback(st *engine.State, d *findingData, now time.Time) {
	if st.Snapshot == nil {
		return
	}
	for _, ref := range d.Pods {
		var best *snapshot.CrashLog
		for _, cl := range st.Snapshot.CrashLogs {
			if cl.Namespace != ref.Namespace || cl.Pod != ref.Name || cl.Error != "" || len(cl.Matches)+len(cl.Lines) == 0 {
				continue
			}
			if best == nil || cl.Container < best.Container {
				best = cl
			}
		}
		if best == nil {
			continue
		}
		d.Matches = best.Matches
		if len(d.Important) == 0 {
			d.Important, d.LogPod, d.LogError = best.Lines, ref, ""
			d.LogSource = fmt.Sprintf("the last crash of %s in %s, read %s", best.Container, best.Pod, agoPlain(now.Sub(best.At)))
		}
		return
	}
}

// logRules are the problems whose explanation is usually in the log of the
// crashed container.
var logRules = map[string]bool{"pod.crashloop": true, "pod.oomkilled": true}

// importantLines reads the log of the last crashed run of an affected pod
// and keeps the lines that look like errors. When the previous run's log is
// gone (the node cleaned up the container), it tries the current run and
// then the next pod: in a crash loop they print the same error.
func (s *Server) importantLines(ctx context.Context, e *engine.Engine, d *findingData) {
	conn := e.Conn()
	if conn == nil {
		return
	}
	pctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	var firstErr string
	for i, ref := range d.Pods {
		if i == 3 {
			break
		}
		p, err := conn.Client.CoreV1().Pods(ref.Namespace).Get(pctx, ref.Name, metav1.GetOptions{})
		if err != nil {
			if firstErr == "" {
				firstErr = fmt.Sprintf("The pod %s could not be read: %v", ref.Name, err)
			}
			continue
		}
		container, previous, crashed := logToExplain(p)
		if container == "" {
			continue
		}
		tries := []bool{previous}
		if previous {
			tries = append(tries, false)
		}
		for _, prev := range tries {
			log, err := podview.ReadLog(pctx, conn.Client, ref.Namespace, ref.Name, podview.LogOptions{Container: container, Previous: prev, Tail: 300})
			if err != nil {
				if firstErr == "" {
					firstErr = fmt.Sprintf("The log of %s could not be read: %s", ref.Name, logError(err))
					s.log.Warn("reading a log for a problem page", "cluster", e.Name(), "pod", ref.Namespace+"/"+ref.Name, "container", container, "previous", prev, "err", err)
				}
				continue
			}
			if lines := podview.ImportantLines(log, 8); len(lines) > 0 {
				d.Important, d.LogPod, d.LogError = lines, ref, ""
				d.Matches = remedy.Find(log)
				d.LogSource = fmt.Sprintf("the %s of %s in %s", ifStr(crashed && prev == previous, "last crashed run", "current run"), container, ref.Name)
				return
			}
		}
	}
	if len(d.Pods) > 0 {
		d.LogPod = d.Pods[0]
	}
	d.LogError = firstErr
}
