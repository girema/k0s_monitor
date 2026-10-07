package web

import (
	"strings"
	"testing"

	"k0s_monitor/internal/findings"
)

func findingIn(t *testing.T, fs []*findings.Finding, rule, resource string) *findings.Finding {
	t.Helper()
	for _, f := range fs {
		if f.RuleID == rule && f.Resource.String() == resource {
			return f
		}
	}
	t.Fatalf("no %s for %s", rule, resource)
	return nil
}

func TestFindingPageExplainsTheCrash(t *testing.T) {
	st := stateOf(t, "crashlog.yaml")
	f := findingIn(t, st.Findings, "pod.crashloop", "shop/deployment/web")
	d := findingData{State: st, F: f}
	for _, a := range f.Affected {
		d.Pods = append(d.Pods, a)
	}
	// No live connection: the log read with the last crash is shown.
	crashLogFallback(st, &d, fixedNow)
	if len(d.Matches) != 1 || d.Matches[0].ID != "missing-setting" || len(d.Important) != 1 || !strings.Contains(d.LogSource, "the last crash of web in web-6f7e8d9c0-q2w3e") {
		t.Fatalf("fallback: matches %+v, lines %v, source %q", d.Matches, d.Important, d.LogSource)
	}
	// The finding explains that error already.
	if d.Matches = otherMatches(f, d.Matches); len(d.Matches) != 0 {
		t.Errorf("matches shown twice: %+v", d.Matches)
	}
	basic, full := renderPage(t, "finding", d)
	mustContain(t, full, "WHAT CHANGED: REVISION 4 → 5", "Every failing pod comes from revision 5",
		"shop/web:1.4.0", "shop/web:1.5.0", "env DATABASE_URL", "changed (value hidden)",
		"rollout undo deploy/web --to-revision=4", "the last crash of web", "environment variable DATABASE_URL is not set")
	mustContain(t, basic, "WHAT THE UPDATE CHANGED", "The app was updated",
		"A setting the app needs (DATABASE_URL) is missing.", "Undo that update first (step 1)",
		// The technical step is folded, for whoever manages the cluster.
		"More checks for whoever manages the cluster", "Add DATABASE_URL to the container",
		// What changed, in its words.
		`<td class="small">setting DATABASE_URL</td>`, `<td class="small">version</td>`)
	for _, page := range []string{basic, full} {
		if strings.Contains(page, "KNOWN ERRORS") || strings.Contains(page, "WHAT THE LOG SAYS") {
			t.Error("the known error is listed again")
		}
	}
	for _, page := range []string{basic, full} {
		for _, secret := range []string{"sk-old", "sk-new", "hunter22"} {
			if strings.Contains(page, secret) {
				t.Errorf("the page shows %s", secret)
			}
		}
	}
}

func TestPodPageExplainsTheExit(t *testing.T) {
	st := stateOf(t, "crashlog.yaml")
	var d podData
	for _, p := range st.Snapshot.Pods {
		if p.Name == "orders-6b5c4d3e2-k8j7h" {
			d = podData{Cluster: "test", Pod: p, Containers: containersOf(p, st.Snapshot), Age: "1 h"}
		}
	}
	if len(d.Containers) != 1 {
		t.Fatalf("containers = %+v", d.Containers)
	}
	c := d.Containers[0]
	if !strings.HasPrefix(c.ExitMeans, "1: a general error") || c.ExitPlain != "the app reported an error and stopped" || len(c.Crash) != 1 {
		t.Errorf("container = %+v", c)
	}
	basic, full := renderPage(t, "pod", d)
	mustContain(t, full, "Code means", "Log says", "Connection refused by 10.96.14.2:5432")
	mustContain(t, basic, "restarted 9 times; the last time, the app reported an error and stopped")
}

func TestFindingPageListsTheOtherErrors(t *testing.T) {
	st := stateOf(t, "crashlog.yaml")
	f := findingIn(t, st.Findings, "pod.crashloop", "shop/deployment/mailer")
	d := findingData{State: st, F: f}
	for _, a := range f.Affected {
		d.Pods = append(d.Pods, a)
	}
	crashLogFallback(st, &d, fixedNow)
	d.Matches = otherMatches(f, d.Matches)
	if len(d.Matches) != 1 || d.Matches[0].ID != "go-panic" {
		t.Fatalf("matches = %+v", d.Matches)
	}
	basic, full := renderPage(t, "finding", d)
	mustContain(t, full, "KNOWN ERRORS IN THE LOG", "Go panic: no mail relay", "1 line", "Check: The stack trace")
	mustContain(t, basic, "WHAT THE LOG SAYS", "The program crashed because of an error it didn&#39;t expect.")
	if strings.Contains(full, "WHAT CHANGED") {
		t.Error("mailer has one revision: nothing to compare")
	}
}

func TestPlainChange(t *testing.T) {
	for what, want := range map[string]string{
		"env DATABASE_URL": "setting DATABASE_URL",
		"env from":         "settings taken from",
		"image":            "version",
		"mount /data":      "folder /data",
		"volume cache":     "storage cache",
		"readiness probe":  "ready check",
		"memory limit":     "memory limit",
		"restarted (kubectl rollout restart), nothing else changed": "restarted, nothing else changed",
	} {
		if got := plainChange(what); got != want {
			t.Errorf("plainChange(%q) = %q, want %q", what, got, want)
		}
	}
}
