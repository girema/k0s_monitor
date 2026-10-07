package snapshot

import (
	"os"
	"testing"
)

func TestParseK0sVersion(t *testing.T) {
	for _, c := range []struct {
		in    string
		build string
		ok    bool
	}{
		{"v1.36.4+k0s.1", "1", true},
		{"v1.36.4+k0s", "", true},
		{"1.36.4", "", true},
		{"v1.36", "", false},
		{"", "", false},
	} {
		v, ok := ParseK0sVersion(c.in)
		if ok != c.ok || ok && (v.Kubernetes() != "v1.36.4" || v.Build != c.build) {
			t.Errorf("%q: %+v %v", c.in, v, ok)
		}
	}
	a, _ := ParseK0sVersion("v1.36.4+k0s.1")
	kubelet, _ := ParseK0sVersion("v1.36.4+k0s")
	other, _ := ParseK0sVersion("v1.36.4+k0s.0")
	older, _ := ParseK0sVersion("v1.36.3+k0s.1")
	if !a.Matches(kubelet) || a.Matches(other) || a.Matches(older) {
		t.Error("matching: a kubelet's version matches its build; other builds and patches don't")
	}
}

func TestExpectedVersion(t *testing.T) {
	s := New(&Snapshot{ControlPlane: &ControlPlane{Controllers: []*Controller{
		{Name: "c1", K0sVersion: "v1.36.3+k0s.0"}, {Name: "c2", K0sVersion: "v1.36.4+k0s.1"},
	}}})
	// A tie goes to the newer version.
	if v, from, ok := s.ExpectedVersion(); !ok || v.Raw != "v1.36.4+k0s.1" || from != "the version most controllers run" {
		t.Errorf("tie: %v %q %v", v.Raw, from, ok)
	}
	s.ExpectedK0s = ExpectedOf("v1.36.3+k0s.0", "")
	if v, from, _ := s.ExpectedVersion(); v.Raw != "v1.36.3+k0s.0" || from != "the configuration file" {
		t.Errorf("set: %v %q", v.Raw, from)
	}
}

func TestParsePlansFromAutopilot(t *testing.T) {
	// What a real k0s v1.36.4+k0s.1 controller answered: a plan naming a
	// worker that doesn't exist, and one whose download failed.
	read := func(name string) []*Plan {
		t.Helper()
		b, err := os.ReadFile("testdata/" + name)
		if err != nil {
			t.Fatal(err)
		}
		ps, err := ParsePlans(b)
		if err != nil || len(ps) != 1 {
			t.Fatalf("%s: %v %v", name, ps, err)
		}
		return ps
	}
	p := read("plans-missing-node.json")[0]
	if p.Name != "autopilot" || p.State != PlanIncompleteTargets || p.Running() || p.Version() != "v1.36.4+k0s.1" ||
		len(p.Targets()) != 1 || p.Targets()[0] != (PlanTarget{Name: "ghost", State: SignalMissingNode, Updated: p.Targets()[0].Updated}) || p.Targets()[0].Updated.IsZero() {
		t.Errorf("missing node: %+v %+v", p, p.Targets())
	}
	p = read("plans-apply-failed.json")[0]
	if p.State != PlanApplyFailed || p.Version() != "v1.36.5+k0s.0" || len(p.Targets()) != 1 || !p.Targets()[0].Controller || p.Targets()[0].State != SignalApplyFailed {
		t.Errorf("apply failed: %+v %+v", p, p.Targets())
	}

	sig, ok := ParseUpdateSignal(map[string]string{SignalDataAnnotation: `{"planId":"e2e-bad-download","created":"2026-09-28T17:52:12Z","command":{"id":0,"k0supdate":{"url":"https://updates.example.invalid/k0s","version":"v1.36.5+k0s.0"}},"status":{"status":"FailedDownload","timestamp":"2026-09-28T17:52:12Z"}}`})
	if !ok || sig.Status != "FailedDownload" || sig.URL != "https://updates.example.invalid/k0s" || SignalStatusText(sig.Status) != "the download failed" {
		t.Errorf("signal: %+v %v", sig, ok)
	}
	if _, ok := ParseUpdateSignal(nil); ok {
		t.Error("no annotation, no signal")
	}
}
