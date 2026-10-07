package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"k0s_monitor/internal/cluster"
	"k0s_monitor/internal/config"
	"k0s_monitor/internal/findings"
	"k0s_monitor/internal/fleet"
	"k0s_monitor/internal/priority"
	"k0s_monitor/internal/rules"
	"k0s_monitor/internal/snapshot"
)

var now = time.Date(2026, 9, 27, 14, 0, 0, 0, time.UTC)

func results(t *testing.T) []*fleet.ClusterResult {
	t.Helper()
	s, err := snapshot.FromYAMLFile("edge-prod", "../rules/testdata/crashloop.yaml", now)
	if err != nil {
		t.Fatal(err)
	}
	fs, _ := fleet.EvaluateSnapshot(s, config.DefaultThresholds(), "")
	good := &fleet.ClusterResult{
		Name: "edge-prod", Status: fleet.StatusOK, Findings: fs,
		Info:   &cluster.Info{Server: "https://10.0.10.5:6443", Version: "v1.36.4+k0s", K0s: true, Nodes: 1, Pods: 3},
		Counts: map[findings.Priority]int{findings.P1: 1},
	}
	for _, f := range fs {
		switch {
		case f.IsSymptom():
			good.Symptoms++
		case f.IsHygiene():
			good.Suggestions++
		}
	}
	ce := &cluster.ConnError{Kind: cluster.KindTimeout, Server: "https://172.16.4.10:6443", Plain: "No answer from 172.16.4.10 on port 6443.", Hint: "Check the network."}
	f := fleet.Unreachable("factory-berlin", ce)
	priority.Apply([]*findings.Finding{f}, nil, "")
	dead := &fleet.ClusterResult{Name: "factory-berlin", Status: fleet.StatusUnreachable, Error: ce,
		Findings: []*findings.Finding{f}, Counts: map[findings.Priority]int{findings.P1: 1}}
	return []*fleet.ClusterResult{good, dead}
}

func render(t *testing.T, o Options) string {
	t.Helper()
	o.Now = now
	var b bytes.Buffer
	if err := Render(&b, results(t), o); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func mustContain(t *testing.T, out string, parts ...string) {
	t.Helper()
	for _, p := range parts {
		if !strings.Contains(out, p) {
			t.Errorf("output lacks %q:\n%s", p, out)
		}
	}
}

func TestTableFull(t *testing.T) {
	out := render(t, Options{Format: Table, Mode: Full})
	mustContain(t, out,
		"k0s-monitor scan · 2026-09-27 14:00 UTC · 2 clusters",
		"edge-prod", "v1.36.4+k0s · 1 node · 3 pods",
		"P1", "85", "pod.crashloop", "shop/deployment/payments-api",
		"↳ deploy.unavailable", "↳ svc.no-endpoints",
		"1 problem: P1 1 · P2 0 · P3 0 · P4 0 (+2 symptoms folded under them), 2 good-practice suggestions",
		"hygiene.no-limits", "hygiene.no-probes",
		"factory-berlin", "cluster.unreachable", "No answer from 172.16.4.10",
		"Total: 2 problems in 2 clusters",
		"Run with -v",
	)
	if strings.Contains(out, "\033[") {
		t.Error("colors must be off unless requested")
	}
}

func TestTableVerboseShowsSteps(t *testing.T) {
	out := render(t, Options{Format: Table, Mode: Full, Verbose: true})
	mustContain(t, out,
		"Exit code: 1 (Error)",
		"Likely cause:",
		"$ k0s kubectl -n shop logs payments-api-7c9f8d6b5-x2kqp -c api --previous",
		"(run on controller)",
	)
}

func TestTableBasic(t *testing.T) {
	out := render(t, Options{Format: Table, Mode: Basic, Verbose: true})
	mustContain(t, out,
		"Fix now", "The app payments-api keeps crashing",
		"Also affected: the app payments-api is down; the service payments-api has nothing behind it",
		"What to do:",
		"The cluster factory-berlin can't be reached",
		"1 fix now",
	)
	if strings.Contains(out, "pod.crashloop") {
		t.Error("Basic mode must not show rule IDs")
	}
	// Good practices are left out of Basic mode.
	if strings.Contains(out, "memory limit") || strings.Contains(out, "suggestion") {
		t.Errorf("Basic mode shows good practices:\n%s", out)
	}
	md := render(t, Options{Format: Markdown, Mode: Basic})
	if strings.Contains(md, "memory limit") {
		t.Error("Basic Markdown shows good practices")
	}
	mustContain(t, render(t, Options{Format: Markdown, Mode: Full}), "hygiene.no-limits")
}

func TestJSON(t *testing.T) {
	out := render(t, Options{Format: JSON})
	var r struct {
		Tool     string `json:"tool"`
		Clusters []struct {
			Name     string `json:"name"`
			Status   string `json:"status"`
			Findings []struct {
				RuleID   string `json:"ruleId"`
				Priority string `json:"priority"`
				Severity string `json:"severity"`
				ParentID string `json:"parentId"`
				Plain    struct {
					Title string `json:"title"`
				} `json:"plain"`
			} `json:"findings"`
			Error *struct {
				Kind string `json:"kind"`
			} `json:"error"`
		} `json:"clusters"`
		Totals map[string]int `json:"totals"`
	}
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if r.Tool != "k0s-monitor" || len(r.Clusters) != 2 || r.Totals["P1"] != 2 {
		t.Fatalf("unexpected report: %+v", r)
	}
	first := r.Clusters[0].Findings[0]
	if first.RuleID != "pod.crashloop" || first.Severity != "critical" || first.Plain.Title == "" {
		t.Errorf("first finding = %+v", first)
	}
	if r.Clusters[1].Status != "unreachable" || r.Clusters[1].Error.Kind != "timeout" {
		t.Errorf("unreachable cluster = %+v", r.Clusters[1])
	}
}

func TestMarkdown(t *testing.T) {
	out := render(t, Options{Format: Markdown, Mode: Full})
	mustContain(t, out,
		"# k0s-monitor scan",
		"## edge-prod",
		"| P1 | 85 | `pod.crashloop` | `shop/deployment/payments-api` |",
		"```sh",
		"## factory-berlin",
		"**Unreachable.**",
	)
}

func TestParse(t *testing.T) {
	if f, err := ParseFormat("md"); err != nil || f != Markdown {
		t.Errorf("md: %v %v", f, err)
	}
	if _, err := ParseFormat("xml"); err == nil {
		t.Error("xml should be rejected")
	}
	if m, err := ParseMode("BASIC"); err != nil || m != Basic {
		t.Errorf("BASIC: %v %v", m, err)
	}
}

func TestSkippedChecksAreGroupedByReason(t *testing.T) {
	const noMetrics = "needs metrics from Prometheus, which are not available"
	got := skippedText([]rules.Skipped{
		{RuleID: "pvc.usage", Reason: noMetrics}, {RuleID: "node.not-ready", Reason: "cannot read nodes"},
		{RuleID: "pvc.fill-forecast", Reason: noMetrics}, {RuleID: "node.fs-high", Reason: noMetrics},
		{RuleID: "vm.cpu-steal", Reason: noMetrics},
	})
	if want := "4 checks (" + noMetrics + "); node.not-ready (cannot read nodes)"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
