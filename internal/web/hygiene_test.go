package web

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"k0s_monitor/internal/account"
	"k0s_monitor/internal/cluster"
	"k0s_monitor/internal/config"
	"k0s_monitor/internal/engine"
	"k0s_monitor/internal/store"
	"k0s_monitor/internal/vault"
)

// hygieneState is the hygiene fixture as the engine publishes it.
func hygieneState(t *testing.T) *engine.State {
	t.Helper()
	st := stateOf(t, "hygiene.yaml")
	for _, f := range st.Findings {
		if f.IsHygiene() {
			st.Suggestions++
		}
	}
	if st.Suggestions != 6 {
		t.Fatalf("suggestions = %d, want 6", st.Suggestions)
	}
	return st
}

func TestSuggestionsAreNotProblems(t *testing.T) {
	st := hygieneState(t)

	// Basic mode: nothing to fix, with a pointer to Full mode.
	basic := problemsOf(st, "", "", false, true)
	if basic.Total != 0 || len(basic.Items) != 0 {
		t.Errorf("basic problems: total %d, items %d", basic.Total, len(basic.Items))
	}
	page, _ := renderPage(t, "problems", basic)
	mustContain(t, page, "Nothing to fix", "6 suggestions about good practices", "category=hygiene")

	// Full mode lists them, in their own category.
	full := problemsOf(st, "", "", false, false)
	if full.Total != 0 || len(full.Items) != 6 || full.Suggestions != 6 {
		t.Errorf("full problems: total %d, items %d, suggestions %d", full.Total, len(full.Items), full.Suggestions)
	}
	var cats []string
	for _, c := range full.CatCounts {
		cats = append(cats, string(c.Category))
	}
	if strings.Join(cats, ",") != "hygiene" {
		t.Errorf("categories = %v", cats)
	}
	_, page = renderPage(t, "problems", full)
	mustContain(t, page, "0 open root causes", "6 good-practice suggestions", "Hygiene", "hygiene.no-limits")
	if only := problemsOf(st, "", "hygiene", false, false); len(only.Items) != 6 {
		t.Errorf("hygiene filter: %d items", len(only.Items))
	}

	// Nor does the overview, the cluster's top problem, or an app's row.
	if ov := overviewOf("test", st); len(ov.Items) != 0 || len(ov.Top) != 0 {
		t.Errorf("overview: %d items", len(ov.Items))
	}
	if f := topRoot(st); f != nil {
		t.Errorf("top root = %s", f.RuleID)
	}
	for _, a := range appsOf(st, appsQuery{}, fixedNow).Apps {
		if a.Top != nil || a.Problems != 0 {
			t.Errorf("app %s has problem %s", a.Name, a.Top.RuleID)
		}
	}
}

func TestSuggestionsDontNotify(t *testing.T) {
	st := hygieneState(t)
	v, _ := vault.New(bytes.Repeat([]byte{1}, vault.KeySize))
	db, err := store.Open(filepath.Join(t.TempDir(), "db"), v)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// Even with every level turned on.
	n := newNotifier(db, newHub(), []string{"fix-now", "fix-today", "plan-ahead", "suggestions"})
	for _, f := range st.Findings {
		n.handle(engine.Event{Type: engine.FindingOpened, Cluster: "test", Finding: f})
	}
	if got, _, _ := db.Notifications("admin", 10); len(got) != 0 {
		t.Errorf("notifications: %+v", got)
	}
}

func TestGlossary(t *testing.T) {
	basic, full := renderPage(t, "glossary", glossaryOf())
	for _, page := range []string{basic, full} {
		mustContain(t, page, `id="t-api-server"`, "also server, servers", "also memory limit, memory limits", "shows their values only when that is turned on in Settings", `href="#t-api-server"`)
		if strings.Contains(page, "also certificates") {
			t.Error("plurals are listed")
		}
	}
	// The problem page explains its terms.
	st := stateOf(t, "node-npd.yaml")
	f := st.Findings[0]
	basic, full = renderPage(t, "finding", findingData{State: st, F: f})
	mustContain(t, basic, `class="term" tabindex="0"`, `role="tooltip"`, "<b>node</b> A machine")
	mustContain(t, full, `class="term"`, "<b>kubelet</b>")
}

func TestGlossaryRoute(t *testing.T) {
	env := newEnv(t, nil)
	env.login()
	body := readBody(t, env.do("GET", "/glossary", nil, nil))
	mustContain(t, body, "<h1>Glossary</h1>", "CrashLoopBackOff", `href="/glossary" class="active"`)
}

func TestTLSFormStates(t *testing.T) {
	st := stateOf(t, "tls.yaml")
	st.Info = &cluster.Info{TLSSecrets: "not allowed"}
	c := config.Cluster{Name: "test", FromUI: true}
	if f := tlsFormOf(c, st, "readonly"); f.Commands != account.TLSSecretsCommands || !f.On || !f.Editable {
		t.Errorf("read-only account: %+v", f)
	}
	// Commands for k0s-monitor's account don't help uploaded credentials.
	if f := tlsFormOf(c, st, "uploaded"); f.Commands != "" || !f.Uploaded {
		t.Errorf("uploaded: %+v", f)
	}
	st.Info.TLSSecrets = "ok"
	off := false
	c.ReadTLSSecrets = &off
	if f := tlsFormOf(c, st, "readonly"); f.Commands != "" || f.Certs != 6 || f.On {
		t.Errorf("ok: %+v", f)
	}
	_, page := renderPage(t, "clustersettings", clusterSettingsData{State: st, FromUI: true, TLS: tlsFormOf(config.Cluster{}, st, "")})
	mustContain(t, page, "reading 6 certificates", "drops the private key")
}
