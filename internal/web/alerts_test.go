package web

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"k0s_monitor/internal/findings"
	"k0s_monitor/internal/priority"
	"k0s_monitor/internal/snapshot"
	"k0s_monitor/internal/store"
)

func TestAlertsPage(t *testing.T) {
	st := stateOf(t, "alerts.yaml")
	d := alertsOf(st, nil, fixedNow)
	if !d.Read || len(d.Rows) != 4 || d.Linked != 3 {
		t.Fatalf("alerts: read %v, %d rows, %d linked", d.Read, len(d.Rows), d.Linked)
	}
	// Most severe first, each with the root problems it is about.
	if d.Rows[0].Name != "KubePersistentVolumeFillingUp" || len(d.Rows[0].Problems) != 1 || d.Rows[0].Problems[0].RuleID != "pvc.fill-forecast" {
		t.Errorf("first row: %+v", d.Rows[0])
	}
	basic, full := renderPage(t, "alerts", d)
	mustContain(t, basic, "Monitoring alerts", "4 alerts; 3 about a problem k0s-monitor found too.", "About app part web-6f7e8d9c0-q2w3e",
		"Problem: <a", "The app web keeps crashing", "k0s-monitor found no problem about this.", "since 15 minutes ago")
	mustContain(t, full, "4 firing alerts in 4 kinds, 3 linked to an issue", "shop/pod/web-6f7e8d9c0-q2w3e", "firing for 15 min",
		`href="https://runbooks.prometheus-operator.dev/runbooks/kubernetes/kubepodcrashlooping"`, "namespace=shop pod=web-6f7e8d9c0-q2w3e", "No issue about this object.")
	if strings.Contains(full, "service=kube-state-metrics") {
		t.Error("Full mode lists the scrape labels")
	}

	// Without Prometheus there is nothing to read, and the page says so.
	st.Snapshot.Metrics.AlertsRead = false
	basic, _ = renderPage(t, "alerts", alertsOf(st, nil, fixedNow))
	mustContain(t, basic, "can't read alerts for this cluster")
}

func TestAlertsOnProblemPages(t *testing.T) {
	st := stateOf(t, "alerts.yaml")
	var crash *findings.Finding
	var children []*findings.Finding
	for _, f := range st.Findings {
		if f.RuleID == "pod.crashloop" {
			crash = f
		}
	}
	for _, f := range st.Findings {
		if f.ParentID == crash.ID {
			children = append(children, f)
		}
	}
	// The app's own alert, once, though its symptom has it too.
	d := findingData{State: st, F: crash, Children: children, Alerts: alertsOfFinding(crash, children)}
	if len(d.Alerts) != 1 || d.Alerts[0].Name != "KubePodCrashLooping" {
		t.Fatalf("alerts: %+v", d.Alerts)
	}
	basic, full := renderPage(t, "finding", d)
	mustContain(t, basic, "Your monitoring warns about this too", "KubePodCrashLooping", "Pod is crash looping.", "All monitoring alerts")
	mustContain(t, full, "Prometheus alerts", "shop/pod/web-6f7e8d9c0-q2w3e</span> · firing for 15 min", ">runbook</a>")

	// The lists tag it.
	pd := problemsOf(st, "", "", false, false)
	basic, full = renderPage(t, "problems", pd)
	mustContain(t, basic, `<span class="tag alert-tag" title="KubePodCrashLooping">monitoring alert</span>`)
	mustContain(t, full, `<span class="tag alert-tag" title="KubePodCrashLooping">KubePodCrashLooping</span>`)

	// The menu shows how many fire, and the overview what they are about.
	if n := navOf(st); !n.AlertsRead || n.Alerts != 4 {
		t.Errorf("nav: %+v", n)
	}
	st.Health = &priority.Health{}
	ov := overviewOf("test", st)
	found := false
	for _, c := range ov.Checks {
		if c.Name == "Monitoring alerts" {
			found = true
			if c.Text != "4 alerts, 3 about the problems here" || c.Icon != "crit" {
				t.Errorf("check: %+v", c)
			}
		}
	}
	if !found {
		t.Errorf("no alerts check: %+v", ov.Checks)
	}
}

// Many alerts of one name from node-exporter: about their servers, shown
// as one group, and hidden by name or on one server.
func TestAlertGroupsAndHiding(t *testing.T) {
	st := stateOf(t, "alerts.yaml")
	m := st.Snapshot.Metrics
	io := func(device string, labels ...string) snapshot.Alert {
		l := map[string]string{"alertgroup": "node-disk", "container": "node-exporter", "namespace": "monitoring", "device": device}
		for i := 0; i+1 < len(labels); i += 2 {
			l[labels[i]] = labels[i+1]
		}
		return snapshot.Alert{Name: "HighIOUtilization", Severity: "critical", Summary: "I/O utilization is high", Labels: l, Since: fixedNow.Add(-12 * 24 * time.Hour)}
	}
	m.Alerts = append(m.Alerts,
		io("sdc", "pod", "node-exporter-7xk2p", "instance", "10.0.0.12:9100"), // worker-2, by its address
		io("sdd", "pod", "node-exporter-7xk2p", "instance", "10.0.0.12:9100"),
		io("sdc", "pod", "node-exporter-a1b2c", "node", "worker-1"))
	group := func(d alertsData, name string) alertGroup {
		for _, g := range d.Groups {
			if g.Name == name {
				return g
			}
		}
		return alertGroup{}
	}
	d := alertsOf(st, nil, fixedNow)
	g := group(d, "HighIOUtilization")
	if g.Name != "HighIOUtilization" || len(g.Rows) != 3 || g.Servers != 2 || !g.Since.Equal(fixedNow.Add(-12*24*time.Hour)) {
		t.Fatalf("group: %+v", g)
	}
	// About the server, not the exporter's pod; by server, each told
	// apart by its device.
	var got []string
	for _, r := range g.Rows {
		got = append(got, r.About.String()+" "+r.Detail)
	}
	if strings.Join(got, "; ") != "node/worker-1 device sdc; node/worker-2 device sdc; node/worker-2 device sdd" {
		t.Errorf("rows: %v", got)
	}
	basic, full := renderPage(t, "alerts", d)
	mustContain(t, basic, "Hide all 3 ▾", "3 alerts on 2 servers", "the first since 12 days ago", "device sdd</b> · About server worker-2", "Hide on worker-2 ▾")
	mustContain(t, full, "firing for up to 12 d", "alertgroup=node-disk device=sdc")
	if strings.Contains(full, "pod=node-exporter") {
		t.Error("Full mode lists the exporter's own pod as if it were the subject")
	}

	// Hidden everywhere: gone from the counts, listed as hidden.
	until := fixedNow.Add(24 * time.Hour)
	d = alertsOf(st, []store.AlertMute{{Name: "HighIOUtilization", Until: &until, By: "ann"}}, fixedNow)
	if d.Shown != 4 || d.Hidden != 3 || len(d.Mutes) != 1 || d.Mutes[0].Hides != 3 || group(d, "HighIOUtilization").Name != "" {
		t.Errorf("hidden everywhere: shown %d, hidden %d, mutes %+v", d.Shown, d.Hidden, d.Mutes)
	}
	basic, _ = renderPage(t, "alerts", d)
	mustContain(t, basic, `<a href="#hidden">3 hidden</a>`, "everywhere", "by ann", "hides 3 alerts now", "Show again")
	// Ended: shown again.
	if d = alertsOf(st, []store.AlertMute{{Name: "HighIOUtilization", Until: &until}}, until.Add(time.Second)); d.Hidden != 0 {
		t.Errorf("an ended hiding still hides %d", d.Hidden)
	}
	// On one server: only its two.
	d = alertsOf(st, []store.AlertMute{{Name: "HighIOUtilization", Server: "worker-2"}}, fixedNow)
	if g := group(d, "HighIOUtilization"); d.Hidden != 2 || len(g.Rows) != 1 || g.Rows[0].Server != "worker-1" {
		t.Errorf("on worker-2: hidden %d, %+v", d.Hidden, g)
	}
}

// Hiding through the server: stored, recorded, applied to the problem
// pages' alerts, and a hiding "while it fires" ends when nothing fires.
func TestHideAlerts(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	s := &Server{o: Options{Store: st}, now: func() time.Time { return fixedNow }, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	r := httptest.NewRequest("POST", "/", nil)
	if err := s.hideAlerts(r, "test", "KubePodCrashLooping", "", "never"); err == nil {
		t.Error("a hiding without a known duration was taken")
	}
	if err := s.hideAlerts(r, "test", "KubePodCrashLooping", "", "firing"); err != nil {
		t.Fatal(err)
	}
	crash := findings.Alert{ID: "a", Name: "KubePodCrashLooping"}
	other := findings.Alert{ID: "b", Name: "Other"}
	if got := s.shownAlerts("test", []findings.Alert{crash, other}); len(got) != 1 || got[0].Name != "Other" {
		t.Errorf("shown: %+v", got)
	}
	if log, _ := st.AuditLog(5); len(log) == 0 || log[0].Action != "alert.hide" || log[0].Detail != "test: KubePodCrashLooping everywhere, while it fires" {
		t.Errorf("audit: %+v", log)
	}
	// Nothing fires any more: the hiding ends.
	state := stateOf(t, "alerts.yaml")
	state.Name = "test"
	state.Snapshot.Metrics.Alerts = nil
	s.alertsFor(state)
	if ms := s.alertMutes("test"); len(ms) != 0 {
		t.Errorf("still hidden: %+v", ms)
	}
	// Shown again by hand.
	_ = s.hideAlerts(r, "test", "Other", "worker-2", "always")
	if err := s.showAlerts(r, "test", "Other", "worker-2"); err != nil || len(s.alertMutes("test")) != 0 {
		t.Errorf("show again: %v %+v", err, s.alertMutes("test"))
	}
}

func TestHideAlertsAPI(t *testing.T) {
	env := newEnv(t, nil)
	env.login()
	hdr := map[string]string{"X-CSRF-Token": env.csrf, "Content-Type": "application/json"}
	resp := env.do("POST", "/api/v1/clusters/edge-prod/alerts/hide", strings.NewReader(`{"name":"HighIOUtilization","server":"worker-2","for":"1w"}`), hdr)
	body := readBody(t, resp)
	if resp.StatusCode != 200 || !strings.Contains(body, `"server": "worker-2"`) || !strings.Contains(body, `"by": "admin"`) {
		t.Fatalf("hide: %d %s", resp.StatusCode, body)
	}
	resp = env.do("POST", "/api/v1/clusters/edge-prod/alerts/hide", strings.NewReader(`{"name":"X","for":"forever"}`), hdr)
	if resp.StatusCode != 400 {
		t.Errorf("an unknown duration: %d", resp.StatusCode)
	}
	resp.Body.Close()
	// The form shows them again.
	form := url.Values{"csrf": {env.csrf}, "action": {"show"}, "name": {"HighIOUtilization"}, "server": {"worker-2"}}
	resp = env.do("POST", "/c/edge-prod/alerts", strings.NewReader(form.Encode()), map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("show form: %d", resp.StatusCode)
	}
	resp.Body.Close()
	if body = readBody(t, env.do("GET", "/api/v1/clusters/edge-prod/alerts", nil, nil)); !strings.Contains(body, `"hidden": []`) {
		t.Errorf("still hidden: %s", body)
	}
	log, _ := env.st.AuditLog(5)
	if len(log) < 2 || log[0].Action != "alert.show" || log[1].Action != "alert.hide" || log[1].Detail != "edge-prod: HighIOUtilization on worker-2, for a week" {
		t.Errorf("audit: %+v", log)
	}
}
