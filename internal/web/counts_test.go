package web

import (
	"fmt"
	"strings"
	"testing"

	"k0s_monitor/internal/engine"
	"k0s_monitor/internal/findings"
	"k0s_monitor/internal/priority"
)

// The Overview's and All clusters' P1–P4 numbers are the Issues page's:
// suggestions count under P4 there too, while the engine's counts (health,
// notifications, the menu) leave them out.
func TestPriorityCountsMatchIssues(t *testing.T) {
	st := stateOf(t, "hygiene.yaml")
	issues := problemsOf(st, "", "", false, false)
	if issues.PCounts[findings.P4] == 0 {
		t.Fatal("the fixture has suggestions")
	}
	d := overviewOf("test", st)
	for _, p := range []findings.Priority{findings.P1, findings.P2, findings.P3, findings.P4} {
		if d.PCounts[p] != issues.PCounts[p] {
			t.Errorf("%s: overview %d, issues %d", p, d.PCounts[p], issues.PCounts[p])
		}
	}
	_, full := renderPage(t, "overview", d)
	mustContain(t, full, fmt.Sprintf(`Hygiene</div><div class="val">%d</div>`, issues.PCounts[findings.P4]))

	st.Counts = map[findings.Priority]int{findings.P1: 0, findings.P2: 0, findings.P3: 0, findings.P4: 0}
	cards := clustersData{Cards: []clusterCard{{State: st, Nav: navOf(st), PCounts: issues.PCounts, Health: nil}}}
	st.Status = engine.StatusConnecting // no health yet: the card shows the counts only
	_, full = renderPage(t, "clusters", cards)
	mustContain(t, full, fmt.Sprintf(`<span class="pri p4">P4</span>%d</span>`, issues.PCounts[findings.P4]))
}

// "What we checked" agrees with the sentence above it: an app down only
// because its server stopped isn't running normally either.
func TestChecksCountFoldedSymptoms(t *testing.T) {
	st := stateOf(t, "nodes.yaml")
	st.Health = &priority.Health{}
	d := overviewOf("test", st)
	checks := map[string]check{}
	for _, c := range d.Checks {
		checks[c.Name] = c
	}
	if c := checks[categoryLabel(findings.Workloads, true)]; c.Icon != "crit" || c.Text != "1 of 1 app has a problem, because of a problem elsewhere" {
		t.Errorf("apps: %+v", c)
	}
	if c := checks[categoryLabel(findings.Nodes, true)]; c.Text != "2 of 3 not responding, and 1 other problem" {
		t.Errorf("servers: %+v", c)
	}
	if c := checks[categoryLabel(findings.Storage, true)]; c.Icon != "good" || c.Text != "working" {
		t.Errorf("storage: %+v", c)
	}
	if !strings.Contains(d.Sentence, "0 of 3 servers and 0 of 1 app run normally") {
		t.Errorf("sentence: %q", d.Sentence)
	}
}
