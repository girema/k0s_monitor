package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseDefaults(t *testing.T) {
	cfg, err := Parse([]byte(`
clusters:
- name: edge-prod
  kubeconfig: /etc/k0s-monitor/edge-prod.conf
thresholds:
  pendingAfter: 30s
`))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Thresholds.PendingAfter.D(); got != 30*time.Second {
		t.Errorf("pendingAfter = %s", got)
	}
	if got := cfg.Thresholds.PVCPendingAfter.D(); got != 2*time.Minute {
		t.Errorf("pvcPendingAfter default = %s", got)
	}
	if cfg.Thresholds.CordonedAfter.D() != 24*time.Hour || cfg.Thresholds.NotReadyAfter.D() != 5*time.Minute || cfg.Thresholds.NamespaceTerminatingAfter.D() != 10*time.Minute {
		t.Errorf("M1 threshold defaults not applied: %+v", cfg.Thresholds)
	}
	if cfg.Thresholds.CrashLoopRestarts != 3 || cfg.Scan.SyncTimeout.D() != time.Minute {
		t.Errorf("defaults not applied: %+v %+v", cfg.Thresholds, cfg.Scan)
	}
}

func TestValidate(t *testing.T) {
	cases := map[string]string{
		"missing name":       "clusters: [{kubeconfig: a}]",
		"bad name":           "clusters: [{name: Edge Prod, kubeconfig: a}]",
		"duplicate":          "clusters: [{name: a, kubeconfig: a}, {name: a, kubeconfig: b}]",
		"missing kubeconfig": "clusters: [{name: a}]",
		"bad proxy":          "clusters: [{name: a, kubeconfig: a, proxy: 'ftp://x'}]",
		"bad criticality":    "clusters: [{name: a, kubeconfig: a, criticality: urgent}]",
		"too many": `clusters: [{name: a, kubeconfig: a}, {name: b, kubeconfig: a}, {name: c, kubeconfig: a},
		  {name: d, kubeconfig: a}, {name: e, kubeconfig: a}, {name: f, kubeconfig: a}]`,
		"unknown field":     "clusters: [{name: a, kubeconfig: a, colour: red}]",
		"bad duration":      "thresholds: {pendingAfter: soon}",
		"negative duration": "thresholds: {pendingAfter: -1m}",
	}
	for name, doc := range cases {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestLoadResolvesRelativeKubeconfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "k0s-monitor.yaml")
	os.WriteFile(path, []byte("clusters: [{name: a, kubeconfig: kubeconfigs/a.conf}]\n"), 0o600)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(dir, "kubeconfigs", "a.conf"); cfg.Clusters[0].Kubeconfig != want {
		t.Errorf("kubeconfig = %q, want %q", cfg.Clusters[0].Kubeconfig, want)
	}
}

func TestDurationJSON(t *testing.T) {
	b, _ := Duration(90 * time.Second).MarshalJSON()
	if string(b) != `"1m30s"` {
		t.Errorf("marshal = %s", b)
	}
	var d Duration
	if err := d.UnmarshalJSON([]byte(`"2m"`)); err != nil || d.D() != 2*time.Minute {
		t.Errorf("unmarshal = %v, %v", d, err)
	}
	if err := d.UnmarshalJSON([]byte(`"x"`)); err == nil || !strings.Contains(err.Error(), "invalid duration") {
		t.Errorf("expected invalid duration error, got %v", err)
	}
}

// The documented example must stay valid and match the defaults it shows.
func TestExampleConfig(t *testing.T) {
	cfg, err := Load("../../examples/k0s-monitor.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Clusters) != 3 || cfg.Clusters[0].Criticality != "high" {
		t.Errorf("clusters = %+v", cfg.Clusters)
	}
	if want := DefaultThresholds(); cfg.Thresholds != want {
		t.Errorf("example thresholds %+v differ from the defaults %+v", cfg.Thresholds, want)
	}
}

func TestPrometheusService(t *testing.T) {
	for in, want := range map[string][4]string{
		"monitoring/prometheus-k8s:9090":            {"monitoring", "prometheus-k8s", "9090", ""},
		"vm/vmselect-main:8481/select/0/prometheus": {"vm", "vmselect-main", "8481", "select/0/prometheus"},
		"vm/vmsingle-main:http/":                    {"vm", "vmsingle-main", "http", ""},
	} {
		p := &Prometheus{Service: in}
		ns, name, port, ok := p.ServiceParts()
		if !ok || [4]string{ns, name, port, p.ServicePath()} != want {
			t.Errorf("%s: %s %s %s %q %v", in, ns, name, port, p.ServicePath(), ok)
		}
	}
	for _, bad := range []string{"prometheus:9090", "monitoring/prometheus", "monitoring/:9090", "monitoring/p:/x"} {
		if _, _, _, ok := (&Prometheus{Service: bad}).ServiceParts(); ok {
			t.Errorf("%s should be refused", bad)
		}
	}
}
